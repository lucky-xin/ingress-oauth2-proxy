package svc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	poauth2 "github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/resolver"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/state"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/jwt"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/signature"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/wrapper"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf/rest"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
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
	BasicAuthzHeader      string
	AccessTokenEndpoint   string
	LogoutEndpoint        string
	AuthorizationEndpoint string
	LoginCallbackUrl      string
	RedirectUriParamName  string
	SessionDomain         string
	RedisCli              redis.UniversalClient
	TokenResolver         *resolver.Resolver
	State                 *state.State
	Checker               authz.Checker
	TokenKey              authz.TokenKey
}

func Create() (*OAuth2Svc, error) {
	client, err := CreateRedis()
	if err != nil {
		return nil, err
	}
	tokenResolver := resolver.Create(client)
	restTokenKey := key.Create(rest.CreateWithEnv(), 6*time.Hour)
	expireMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CACHE_EXPIRE_SECONDS", 6*time.Hour.Milliseconds())
	cleanupMs := env.GetInt64("OAUTH2_ENCRYPTION_CONF_CACHE_CLEANUP_SECONDS", 6*time.Hour.Milliseconds())
	checker, err := wrapper.Create(
		tokenResolver,
		restTokenKey,
		map[oauth2.TokenType]authz.Checker{
			oauth2.OAUTH2: jwt.CreateWithEnv(),
			oauth2.SIGN: signature.CreateWithRest(
				env.GetString("OAUTH2_SIGN_ENCRYPTION_CONF_URL", "http://127.0.0.1:4000/oauth2/encryption-conf"),
				time.Duration(expireMs)*time.Millisecond,
				time.Duration(cleanupMs)*time.Millisecond,
				tokenResolver,
			),
		},
	)
	if err != nil {
		return nil, err
	}
	clientId := os.Getenv("OAUTH2_CLIENT_ID")
	accessTokenEndpoint := env.GetString("OAUTH2_ACCESS_TOKEN_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth/token")
	authorizationEndpoint := env.GetString("OAUTH2_AUTHORIZATION_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth2/authorize")
	logoutEndpoint := env.GetString("OAUTH2_LOGOUT_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com/oauth2/logout")
	oauth2ProxyEndpoint := env.GetString("OAUTH2_PROXY_ENDPOINT", "http://127.0.0.1:80")
	basicAuth := oauth2.CreateBasicAuth(clientId, os.Getenv("OAUTH2_CLIENT_SECRET"))
	auth2Svc := &OAuth2Svc{
		AccessTokenEndpoint:   accessTokenEndpoint,
		AuthorizationEndpoint: authorizationEndpoint,
		LogoutEndpoint:        logoutEndpoint,
		Scope:                 os.Getenv("OAUTH2_SCOPE"),
		BasicAuthzHeader:      basicAuth,
		ClientId:              clientId,
		RedisCli:              client,
		LoginCallbackUrl:      fmt.Sprintf("%s/callback", oauth2ProxyEndpoint),
		RedirectUriParamName:  env.GetString("OAUTH2_REDIRECT_URI_PARAM_NAME", "ru"),
		TokenResolver:         tokenResolver,
		SessionDomain:         env.GetString("OAUTH2_SESSION_DOMAIN", ".xyz.com"),
		Checker:               checker,
		TokenKey:              restTokenKey,
	}

	auth2Svc.State = state.Create(client, time.Minute*5, auth2Svc.RedirectUriParamName)
	return auth2Svc, nil
}

// ExchangeByCode get access token by code
func (svc *OAuth2Svc) ExchangeByCode(code, redirectUri string) (token *poauth2.TokenInf, err error) {
	//http://localhost:3000/oauth/token?scope=openapi&grant_type=authorization_code&
	//redirect_uri=http://192.168.1.103:6666/callback&code=xxx
	url := fmt.Sprintf(`%s?scope=%s&grant_type=authorization_code&redirect_uri=%s&code=%s`,
		svc.AccessTokenEndpoint, svc.Scope, redirectUri, code)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", svc.BasicAuthzHeader)
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
	var tokenResp *poauth2.TokenResp
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
	tk, err := svc.TokenKey.Get()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	claims, err := svc.Checker.CheckWithContext(tk, c)
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
	s, err := svc.State.Create(c)
	if err != nil {
		log.Println("login handler, unable create s: " + err.Error())
		panic(err)
		return
	}
	redirectUri = fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
		svc.AuthorizationEndpoint, svc.ClientId, svc.Scope, s, svc.LoginCallbackUrl)
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
	t := &oauth2.Token{Type: oauth2.OAUTH2, Value: token.AccessToken}
	tk, err := svc.TokenKey.Get()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	details, err := svc.Checker.Check(tk, t)
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
	t *oauth2.Token,
	claims *oauth2.XyzClaims) error {
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
