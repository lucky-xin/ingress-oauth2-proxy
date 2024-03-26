package xyz

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// (demo)[https://mac-blog.org.ua/kubernetes-oauth2-proxy/]
var (
	SessionName      = "oauth2_proxy"
	sessUserInfoName = "_principal_"
	httpClient       = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

type OAuth2Svc struct {
	ClientId              string
	Scope                 string
	AuthorizationHeader   string
	AccessTokenEndpoint   string
	LogoutEndpoint        string
	AuthorizationEndpoint string
	LoginCallbackUrl      string
	RedirectUriParamName  string
	SessionDomain         string
	RedisCli              redis.UniversalClient
	TokenResolver         *OAuth2ProxyTokenResolver
	State                 State
	Checker               types.Checker
	TokenKey              types.TokenKey
}

func Create() (*OAuth2Svc, error) {
	client, err := InitRedis()
	if err != nil {
		return nil, err
	}
	resolver := NewTokenResolver(client)
	confSvc := sign.NewRestEncryptionInfSvc("http://127.0.0.1:4000/oauth2/encryption-conf/app-id")
	checker, err := authz.NewChecker(
		resolver,
		authz.RestTokenKey,
		map[types.TokenType]types.Checker{
			types.OAUTH2: authz.NewTokenChecker([]string{"HS512"}, resolver),
			types.SIGN:   authz.NewSignChecker(confSvc, resolver),
		},
	)
	if err != nil {
		return nil, err
	}
	clientId := os.Getenv("OAUTH2_CLIENT_ID")
	accessTokenEndpoint := env.GetString("OAUTH2_ACCESS_TOKEN_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth2/token")
	authorizationEndpoint := env.GetString("OAUTH2_AUTHORIZATION_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth2/authorize")
	logoutEndpoint := env.GetString("OAUTH2_LOGOUT_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth2/logout")
	oauth2ProxyEndpoint := env.GetString("OAUTH2_PROXY_ENDPOINT", "http://127.0.0.1:80")
	stringToSign := clientId + ":" + os.Getenv("OAUTH2_CLIENT_SECRET")
	signature := "Basic " + base64.StdEncoding.EncodeToString([]byte(stringToSign))

	auth2Svc := &OAuth2Svc{
		AccessTokenEndpoint:   accessTokenEndpoint,
		AuthorizationEndpoint: authorizationEndpoint,
		LogoutEndpoint:        logoutEndpoint,
		Scope:                 os.Getenv("OAUTH2_SCOPE"),
		AuthorizationHeader:   signature,
		ClientId:              clientId,
		RedisCli:              client,
		LoginCallbackUrl:      fmt.Sprintf("%s/callback", oauth2ProxyEndpoint),
		RedirectUriParamName:  env.GetString("OAUTH2_REDIRECT_URI_PARAM_NAME", "ru"),
		TokenResolver:         resolver,
		SessionDomain:         env.GetString("OAUTH2_SESSION_DOMAIN", ".xyz.com"),
		Checker:               checker,
		TokenKey:              authz.RestTokenKey,
	}

	auth2Svc.State = CreateStateRedis(client, time.Minute*5, auth2Svc.RedirectUriParamName)
	return auth2Svc, nil
}

// ExchangeByCode get access token by code
func (svc *OAuth2Svc) ExchangeByCode(code, redirectUri string) (token *TokenInf, err error) {
	reqBody := map[string]interface{}{
		"scope":        svc.Scope,
		"grant_type":   "authorization_code",
		"redirect_uri": redirectUri,
		"code":         code,
	}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", svc.AccessTokenEndpoint, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", svc.AuthorizationHeader)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var tokenResp *TokenResp
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, err
	}
	if tokenResp.Code != 1 {
		return nil, errors.New(tokenResp.Msg)
	}
	return &tokenResp.Data, nil
}

func (svc *OAuth2Svc) Check(c *gin.Context) {
	token := svc.TokenResolver.Resolve(c)
	if token == nil {
		log.Println("not found access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	key, err := svc.TokenKey()
	if err != nil {
		log.Println("invalid access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	claims, err := svc.Checker.CheckWithContext(key, c)
	if err != nil {
		log.Println("invalid access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}

	err = svc.CreateSession(c, token, claims)
	if err != nil {
		log.Println("cannot save session: ", err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unauthorized"))
		return
	}

	c.Header("X-Auth-Request-User-Id", strconv.FormatInt(claims.UserId, 20))
	c.Header("X-Auth-Request-User-Name", claims.Username)
	c.Header("Authorization", string(token.Type)+" "+token.Value)
	log.Println("check handler authenticated")
	c.JSON(http.StatusOK, r.Succeed("authenticated"))
	return
}

func (svc *OAuth2Svc) Login(c *gin.Context) {
	redirectUri := c.Query(svc.RedirectUriParamName)
	if redirectUri == "" {
		panic("not found redirect uri in request in param name:" + svc.RedirectUriParamName)
		return
	}
	state, err := svc.State.Create(c)
	if err != nil {
		log.Println("login handler, unable create state: " + err.Error())
		panic(err)
		return
	}
	redirectUri = fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
		svc.AuthorizationEndpoint, svc.ClientId, svc.Scope, state, svc.LoginCallbackUrl)
	log.Println("login handler, redirecting to: " + redirectUri)
	c.Redirect(http.StatusMovedPermanently, redirectUri)
}

func (svc *OAuth2Svc) Callback(c *gin.Context) {
	stateInf, err := svc.State.Get(c)
	if err != nil {
		log.Println("unable to get state: " + err.Error())
		panic(err)
		return
	}
	code := c.Query("code")
	token, err := svc.ExchangeByCode(code, svc.LoginCallbackUrl)
	if err != nil {
		log.Println("unable to exchange code for access token: " + err.Error())
		panic(err)
		return
	}
	t := &types.Token{Type: types.OAUTH2, Value: token.AccessToken}
	key, err := svc.TokenKey()
	if err != nil {
		log.Println("invalid access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	details, err := svc.Checker.Check(key, t)
	if err != nil {
		log.Println("decode token err: " + err.Error())
		panic(err)
		return
	}
	err = svc.CreateSession(c, t, details)
	if err != nil {
		log.Println("callback handler, unable to save access token to session: " + err.Error())
		panic(err)
		return
	}
	log.Println("callback handler, redirecting to: " + stateInf.RedirectUri)
	c.Redirect(http.StatusMovedPermanently, stateInf.RedirectUri)
}

func (svc *OAuth2Svc) CreateSession(
	c *gin.Context,
	t *types.Token,
	claims *types.XyzClaims) error {
	sess := sessions.Default(c)
	log.Println("session id:" + sess.ID())
	expire := claims.ExpiresAt.Second() - claims.IssuedAt.Second()
	sess.Options(sessions.Options{
		Domain:   svc.SessionDomain,
		Path:     "/",
		MaxAge:   expire,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	sess.Set(sessUserInfoName, map[string]interface{}{
		"uid":   claims.UserId,
		"uname": claims.Username,
		"tid":   claims.TenantId,
	})
	err := svc.TokenResolver.Save(c, t, time.Second*time.Duration(expire))
	if err != nil {
		return err
	}

	return sess.Save()
}

func (svc *OAuth2Svc) Logout(c *gin.Context) {
	token := svc.TokenResolver.Resolve(c)
	if token != nil {
		req, err := http.NewRequest("DELETE", svc.AccessTokenEndpoint, bytes.NewBuffer(nil))
		if err != nil {
			panic(err)
			return
		}
		req.Header.Set("Authorization", string(token.Type)+" "+token.Value)
		_, err = httpClient.Do(req)
		if err != nil {
			panic(err)
			return
		}
	}

	sess := sessions.Default(c)
	sess.Clear()

	svc.TokenResolver.Del(c)
	redirectUri := c.Query(svc.RedirectUriParamName)
	if redirectUri == "" {
		return
	}
	c.Redirect(http.StatusFound, redirectUri)
}
