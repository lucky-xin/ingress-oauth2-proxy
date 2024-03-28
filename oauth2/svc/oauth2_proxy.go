package svc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	poauth2 "github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/session"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/state"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/wrapper"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/encrypt/conf/rest"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
	xresolver "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	AuthorizationEndpoint string
	LogoutEndpoint        string

	LoginCallbackUrl     string
	RedirectUriParamName string
	SessionDomain        string
	RedisCli             redis.UniversalClient
	TokenResolver        xresolver.TokenResolver
	State                *state.State
	Checker              authz.Checker
	TokenKey             authz.TokenKey
}

func Create() (*OAuth2Svc, error) {
	client, err := CreateRedis()
	if err != nil {
		return nil, err
	}
	checker := wrapper.CreateWithEnv()
	clientId := os.Getenv("OAUTH2_CLIENT_ID")
	accessTokenEndpoint := env.GetString("OAUTH2_ACCESS_TOKEN_ENDPOINT",
		"https://d-it-auth.gzv-k8s.xyz.com/oauth/token")
	authorizationEndpoint := env.GetString("OAUTH2_AUTHORIZATION_ENDPOINT",
		"https://d-it-auth.gzv-k8s.xyz.com/oauth2/authorize")
	logoutEndpoint := env.GetString("OAUTH2_LOGOUT_ENDPOINT",
		"https://d-it-auth.gzv-k8s.xyz.com/oauth2/logout")
	oauth2ProxyEndpoint := env.GetString("OAUTH2_PROXY_ENDPOINT", "http://127.0.0.1:80")

	auth2Svc := &OAuth2Svc{
		AccessTokenEndpoint:   accessTokenEndpoint,
		AuthorizationEndpoint: authorizationEndpoint,
		LogoutEndpoint:        logoutEndpoint,
		Scope:                 os.Getenv("OAUTH2_SCOPE"),
		BasicAuthzHeader:      oauth2.CreateBasicAuth(clientId, os.Getenv("OAUTH2_CLIENT_SECRET")),
		ClientId:              clientId,
		RedisCli:              client,
		LoginCallbackUrl:      fmt.Sprintf("%s/callback", oauth2ProxyEndpoint),
		RedirectUriParamName:  env.GetString("OAUTH2_REDIRECT_URI_PARAM_NAME", "ru"),
		TokenResolver:         checker.GetTokenResolver(),
		SessionDomain:         env.GetString("OAUTH2_SESSION_DOMAIN", ".xyz.com"),
		Checker:               checker,
		TokenKey:              key.Create(rest.CreateWithEnv(), 6*time.Hour),
	}
	auth2Svc.State = state.Create(client, time.Minute*5, auth2Svc.RedirectUriParamName)
	return auth2Svc, nil
}

// ExchangeByCode get access token by code
func (svc *OAuth2Svc) ExchangeByCode(code, redirectUri string) (token *poauth2.TokenInf, err error) {
	// http:127.0.0.1:3000/oauth/token?scope=read&grant_type=authorization_code&redirect_uri=
	//https://www.pistonidata.com&code=
	reader := strings.NewReader(fmt.Sprintf("scope=%s&grant_type=authorization_code&redirect_uri=%s&code=%s",
		svc.Scope, redirectUri, code))
	req, err := http.NewRequest("POST", svc.AccessTokenEndpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", svc.BasicAuthzHeader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	var tokenResp *poauth2.TokenInf
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, err
	}
	return tokenResp, nil
}

// Check 验证Context之中是否有验证信息，验证成功返回200状态码，否则返回400和其他状态码
func (svc *OAuth2Svc) Check(c *gin.Context) {
	// 1.尝试从session之中获取认证信息
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	cache := svc.RedisCli.HGetAll(context.Background(), session.TokenKey(sess.ID())).Val()
	if cache != nil {
		// session 有认证信息直接返回
		c.Header("X-Auth-Request-User-Id", strutil.ToString(cache["uid"]))
		c.Header("X-Auth-Request-User-Name", strutil.ToString(cache["uname"]))
		c.Header("Authorization", strutil.ToString(cache["type"])+" "+strutil.ToString(cache["value"]))
		c.JSON(http.StatusOK, r.Succeed("authenticated"))
		return
	}

	// 2.尝试从请求头，URL参数之中获取token
	token := svc.TokenResolver.Resolve(c)
	if token == nil {
		log.Println("not found access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 3.获取JWT token key
	tk, err := svc.TokenKey.Get()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 4.校验token
	claims, err := svc.Checker.CheckWithContext(tk, c)
	if err != nil {
		log.Println("invalid access token")
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 5.新建session，cookie，并将认证结果存入session之中
	err = svc.CreateSession(c, token, claims)
	if err != nil {
		log.Println("cannot save session: ", err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unauthorized"))
		return
	}
	// 6.token校验成功，将认证信息添加到当前请求头
	c.Header("X-Auth-Request-User-Id", strconv.FormatInt(claims.UserId, 20))
	c.Header("X-Auth-Request-User-Name", claims.Username)
	c.Header("Authorization", string(token.Type)+" "+token.Value)
	c.JSON(http.StatusOK, r.Succeed("authenticated"))
	return
}

// Login 登录，基于OAuth2 authorize endpoint实现，获取原始访问地址redirectUri保存到Redis缓存之中，认证成功之后
// 从Redis之中获取redirectUri，再将请求转发到该地址
func (svc *OAuth2Svc) Login(c *gin.Context) {
	// 获取原始访问地址
	redirectUri := c.Query(svc.RedirectUriParamName)
	if redirectUri == "" {
		panic("not found redirect uri in request in param name:" + svc.RedirectUriParamName)
		return
	}
	// 新建State，并将redirectUri保存
	s, err := svc.State.Create(c)
	if err != nil {
		log.Println("login handler, unable create s: " + err.Error())
		panic(err)
		return
	}
	// 将请求转发到OAuth2 authorize endpoint
	redirectUri = fmt.Sprintf("%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
		svc.AuthorizationEndpoint, svc.ClientId, svc.Scope, s, svc.LoginCallbackUrl)
	log.Println("login handler, redirecting to: " + redirectUri)
	c.Redirect(http.StatusMovedPermanently, redirectUri)
}

// Callback OAuth2 authorize endpoint认证成功回调接口
func (svc *OAuth2Svc) Callback(c *gin.Context) {
	// 从Redis之中获取State
	stateInf, err := svc.State.Get(c)
	if err != nil {
		log.Println("unable to get state: " + err.Error())
		panic(err)
		return
	}
	// 根据code获取access token
	code := c.Query("code")
	token, err := svc.ExchangeByCode(code, svc.LoginCallbackUrl)
	if err != nil {
		log.Println("unable to exchange code for access token: " + err.Error())
		panic(err)
		return
	}
	t := &oauth2.Token{Type: oauth2.OAUTH2, Value: token.AccessToken}
	// 获取JWT 解析key
	tk, err := svc.TokenKey.Get()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 解析token
	details, err := svc.Checker.Check(tk, t)
	if err != nil {
		log.Println("decode token err: " + err.Error())
		panic(err)
		return
	}
	// 新建session，cookie并将认证信息存入session之中
	err = svc.CreateSession(c, t, details)
	if err != nil {
		log.Println("callback handler, unable to save access token to session: " + err.Error())
		panic(err)
		return
	}
	log.Println("callback handle succeed, redirecting to: " + stateInf.RedirectUri)
	// 将请求转发到原来的地址
	c.Redirect(http.StatusMovedPermanently, stateInf.RedirectUri)
}

func (svc *OAuth2Svc) CreateSession(
	c *gin.Context,
	t *oauth2.Token,
	claims *oauth2.XyzClaims) (err error) {
	ses := sessions.Default(c)
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	log.Println("Creating ses... id:", ses.ID())
	ses.Options(sessions.Options{
		Domain:   svc.SessionDomain,
		Path:     "/",
		MaxAge:   int(expire.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	err = svc.saveToken(c, t, expire)
	if err != nil {
		return
	}
	ses.Set(sessUserInfoName, map[string]interface{}{
		"uid":   claims.UserId,
		"uname": claims.Username,
		"tid":   claims.TenantId,
	})
	err = ses.Save()
	log.Println("Created ses id:", ses.ID())
	return
}

func (svc *OAuth2Svc) saveToken(
	c *gin.Context,
	t *oauth2.Token,
	expire time.Duration) error {
	sess := sessions.Default(c)
	tokenKey := session.TokenKey(sess.ID())
	result := svc.RedisCli.Exists(context.Background(), tokenKey).Val()
	if result != 0 {
		return nil
	}
	values := map[string]string{
		"type":  string(t.Type),
		"value": t.Value,
		"uid":   strconv.FormatInt(t.Uid, 10),
		"uname": t.Uname,
	}
	if t.Params != nil {
		marshal, err := json.Marshal(t.Params)
		if err != nil {
			return err
		}
		values["params"] = string(marshal)
	}
	err := svc.RedisCli.HMSet(context.Background(), tokenKey, values).Err()
	if err != nil {
		return err
	}
	return svc.RedisCli.Expire(context.Background(), tokenKey, expire).Err()
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

	svc.delToken(c)
	redirectUri := c.Query(svc.RedirectUriParamName)
	if redirectUri == "" {
		return
	}
	c.Redirect(http.StatusFound, redirectUri)
}

func (svc *OAuth2Svc) delToken(c *gin.Context) {
	sess := sessions.Default(c)
	svc.RedisCli.Del(context.Background(), session.TokenKey(sess.ID()))
}
