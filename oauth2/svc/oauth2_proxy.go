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

var (
	sessUserInfoName = "_principal_"
	sessStateName    = "_state_"
	stateName        = "state"
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

	auth2Svc.State = state.Create(client, time.Minute*5, auth2Svc.RedirectUriParamName,
		env.GetString("OAUTH2_STATE_SECRET", "EXr88Hc6VQiXxetsgO"))
	return auth2Svc, nil
}

// ExchangeAccessTokenByCode get access token by code
func (svc *OAuth2Svc) ExchangeAccessTokenByCode(code, redirectUri string) (token *poauth2.TokenInf, err error) {
	// http:127.0.0.1:3000/oauth/token?scope=read&grant_type=authorization_code&redirect_uri=
	//https://www.pistonidata.com&code=
	reader := strings.NewReader(fmt.Sprintf("scope=%s&grant_type=authorization_code&redirect_uri=%s&code=%s",
		svc.Scope, redirectUri, code))
	req, err := http.NewRequest(http.MethodPost, svc.AccessTokenEndpoint, reader)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", svc.BasicAuthzHeader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &token)
	return
}

// Check 验证Context之中是否有验证信息，验证成功返回200状态码，否则返回400和其他状态码
func (svc *OAuth2Svc) Check(c *gin.Context) {
	// 1.尝试从session之中获取认证信息
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	if sess.ID() != "" {
		token := &oauth2.Token{}
		err := svc.RedisCli.HGetAll(context.Background(), session.TokenKey(sess.ID())).Scan(token)
		if err == nil {
			byts, _ := json.Marshal(token)
			log.Println("found cache...", string(byts))
			// session 有认证信息直接返回
			c.Header("X-Auth-Request-User-Id", strconv.FormatInt(token.Uid, 10))
			c.Header("X-Auth-Request-User-Name", token.Uname)
			c.Header("Authorization", string(token.Type)+" "+token.Value)
			c.JSON(http.StatusOK, r.Succeed("authenticated"))
			return
		}
	}

	// 2.尝试从请求头，URL参数之中获取token
	token, err := svc.TokenResolver.Resolve(c)
	if err != nil || token == nil {
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
		c.JSON(http.StatusInternalServerError,
			r.Failed("not found redirect uri in request in param name:"+svc.RedirectUriParamName))
		return
	}
	// 新建State，并将redirectUri保存
	s, err := svc.State.Create(c)
	if err != nil {
		log.Println("unable create state: " + err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unable create state"))
		return
	}
	_, err = svc.createSession(c, time.Second*10, sessStateName, s)
	if err != nil {
		log.Println("unable create session: " + err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unable create session"))
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
	// 获取Redis之中State
	stateRedis, err := svc.State.Get(c)
	// 获取session中State
	ses := sessions.Default(c)
	stateSession := ses.Get(sessStateName)
	b := err != nil
	if b || stateRedis == nil || stateRedis.Value != stateSession {
		var msg string
		if b {
			msg = err.Error()
		}
		log.Println("invalid state: " + msg)
		c.JSON(http.StatusUnauthorized, r.Failed("invalid state"))
		return
	}
	// 根据code获取access token
	code := c.Query("code")
	token, err := svc.ExchangeAccessTokenByCode(code, svc.LoginCallbackUrl)
	if err != nil {
		log.Println("unable to exchange code for access token: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to exchange code for access token"))
		return
	}

	// 获取JWT 解析key
	tk, err := svc.TokenKey.Get()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("get token key failed"))
		return
	}
	// 解析token
	t := &oauth2.Token{Type: oauth2.OAUTH2, Value: token.AccessToken}
	details, err := svc.Checker.Check(tk, t)
	if err != nil {
		log.Println("decode token err: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("decode token failed"))
		return
	}
	// 新建session，cookie并将认证信息存入session之中
	err = svc.CreateSession(c, t, details)
	if err != nil {
		log.Println("callback handler, unable to save access token to session: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to save access token to session"))
		return
	}
	ses.Delete(sessStateName)
	log.Println("callback handle succeed, redirecting to: " + stateRedis.RedirectUri)
	// 将请求转发到原来的地址
	c.Redirect(http.StatusMovedPermanently, stateRedis.RedirectUri)
}

func (svc *OAuth2Svc) CreateSession(c *gin.Context, t *oauth2.Token, claims *oauth2.XyzClaims) (err error) {
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	// 必须先执行Session.Save()才能拿到Session id
	ses, err := svc.createSession(c, expire, sessUserInfoName, map[string]interface{}{
		"uid":   claims.UserId,
		"tid":   claims.TenantId,
		"uname": claims.Username,
	})
	tokenKey := session.TokenKey(ses.ID())
	result, err := svc.RedisCli.Exists(context.Background(), tokenKey).Result()
	if result != 0 {
		return nil
	}
	// 不保存params信息
	err = svc.RedisCli.HSet(context.Background(), tokenKey, map[string]interface{}{
		"tid":   t.Tid,
		"uid":   t.Uid,
		"uname": t.Uname,
		"type":  string(t.Type),
		"value": t.Value,
	}).Err()
	if err != nil {
		return err
	}
	err = svc.RedisCli.Expire(context.Background(), tokenKey, expire).Err()
	if err != nil {
		return
	}
	log.Println("Created ses id:", ses.ID())
	return
}

func (svc *OAuth2Svc) createSession(c *gin.Context, expire time.Duration, key, val interface{}) (ses sessions.Session, err error) {
	ses = sessions.Default(c)
	log.Println("Creating ses... id:", ses.ID())
	ses.Options(sessions.Options{
		Domain:   svc.SessionDomain,
		Path:     "/",
		MaxAge:   int(expire.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	ses.Set(key, val)
	// 必须先执行Session.Save()才能拿到Session id
	err = ses.Save()
	log.Println("Created ses id:", ses.ID())
	return
}

func (svc *OAuth2Svc) Logout(c *gin.Context) {
	token, err := svc.TokenResolver.Resolve(c)
	if err != nil || token == nil {
		c.JSON(http.StatusForbidden, r.Failed("not found access token"))
		return
	}

	req, err := http.NewRequest(http.MethodDelete, svc.AccessTokenEndpoint, bytes.NewBuffer(nil))
	if err != nil {
		c.JSON(http.StatusInternalServerError, r.Failed("create delete request failed"))
		return
	}
	req.Header.Set("Authorization", string(token.Type)+" "+token.Value)
	_, err = httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, r.Failed("send delete request failed"))
		return
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
