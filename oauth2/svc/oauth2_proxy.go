//Copyright © 2024 chaoxin.lu
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package svc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/session"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz/wrapper"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/key"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

type SuccessHandler = func(c *gin.Context, token *oauth2.Token, details *oauth2.UserDetails)

type OAuth2Svc struct {
	ClientId             string
	Scope                string
	BasicAuthzHeader     string
	OAuth2IssuerEndpoint string
	Checker              authz.Checker
	TokenKey             authz.TokenKeySvc

	LoginCallbackEndpoint string
	RedirectUriParamName  string
	SessionDomain         string
	RedisCli              redis.UniversalClient
	Session               *session.Session
	SuccessHandler        SuccessHandler
}

func Create() (*OAuth2Svc, error) {
	client, err := CreateRedis()
	if err != nil {
		return nil, err
	}
	checker := wrapper.CreateWithEnv()
	clientId := os.Getenv("OAUTH2_CLIENT_ID")
	issuerEndpoint := env.GetString("OAUTH2_ISSUER_ENDPOINT", "https://d-it-auth.gzv-k8s.xyz.com")
	oauth2ProxyEndpoint := env.GetString("OAUTH2_PROXY_ENDPOINT", "http://127.0.0.1:80")
	ruParamName := env.GetString("OAUTH2_REDIRECT_URI_PARAM_NAME", "ru")
	auth2Svc := &OAuth2Svc{
		OAuth2IssuerEndpoint:  issuerEndpoint,
		Scope:                 os.Getenv("OAUTH2_SCOPE"),
		BasicAuthzHeader:      oauth2.CreateBasicAuth(clientId, os.Getenv("OAUTH2_CLIENT_SECRET")),
		ClientId:              clientId,
		RedisCli:              client,
		LoginCallbackEndpoint: fmt.Sprintf("%s/callback", oauth2ProxyEndpoint),
		RedirectUriParamName:  ruParamName,
		Checker:               checker,
		TokenKey:              key.CreateWithEnv(),
		SuccessHandler:        successHandler,
	}

	auth2Svc.Session = session.Create(
		env.GetString("OAUTH2_SESSION_DOMAIN", ".xyz.com"),
		ruParamName,
		time.Duration(env.GetInt64("OAUTH2_SESSION_STATE_EXPIRE_MS", 3*time.Minute.Milliseconds()))*time.Millisecond,
		client,
	)
	return auth2Svc, nil
}

// ExchangeAccessTokenByCode get access token by code
func (svc *OAuth2Svc) ExchangeAccessTokenByCode(code, redirectUri string) (token *oauth2.Token, err error) {
	// http:127.0.0.1:3000/oauth/token?scope=read&grant_type=authorization_code&redirect_uri=
	//https://www.pistonidata.com&code=
	reader := strings.NewReader(fmt.Sprintf("scope=%s&grant_type=authorization_code&redirect_uri=%s&code=%s",
		svc.Scope, redirectUri, code))
	accessTokenEndpoint := svc.OAuth2IssuerEndpoint + "/oauth/token"
	req, err := http.NewRequest(http.MethodPost, accessTokenEndpoint, reader)
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
	token = &oauth2.Token{}
	err = json.Unmarshal(body, &token)
	if err == nil {
		token.Type = oauth2.OAUTH2
	}
	return
}

func (svc *OAuth2Svc) RefreshToken(refreshToken string) (token *oauth2.Token, err error) {
	accessTokenEndpoint := svc.OAuth2IssuerEndpoint + "/oauth/token"
	formData := url.Values{}
	formData.Set("scope", svc.Scope)
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	if req, err := http.NewRequest(http.MethodPost, accessTokenEndpoint, strings.NewReader(formData.Encode())); err != nil {
		return nil, err
	} else {
		req.Header.Set("Authorization", svc.BasicAuthzHeader)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if resp, err := httpClient.Do(req); err == nil {
			defer func(body io.ReadCloser) {
				err := body.Close()
				if err != nil {
					log.Println(err)
				}
			}(resp.Body)
			byts, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			token = &oauth2.Token{}
			err = json.Unmarshal(byts, token)
			if err != nil {
				return nil, err
			}
			return token, nil
		} else {
			return nil, err
		}
	}
}

// Check 验证Context之中是否有验证信息，验证成功返回200状态码，否则返回400和其他状态码
func (svc *OAuth2Svc) Check(c *gin.Context) {

	// 1.尝试从session之中获取认证信息
	sess := sessions.Default(c)
	log.Println("Check...", sess.ID())
	if sess.ID() != "" {
		cacheToken := &oauth2.Token{}
		details := &oauth2.UserDetails{}
		tokenKey := session.TokenKey(sess.ID())
		detailsKey := session.DetailsKey(sess.ID())
		err1 := svc.RedisCli.Get(context.Background(), tokenKey).Scan(cacheToken)
		err2 := svc.RedisCli.Get(context.Background(), detailsKey).Scan(details)
		if err1 == nil && err2 == nil && cacheToken != nil && details != nil {
			svc.TryRefreshToken(c)
			// session 有认证信息直接返回
			svc.SuccessHandler(c, cacheToken, details)
			return
		}
	}

	// 2.尝试从请求头，URL参数之中获取token
	log.Println("try get token from session, session id:" + sess.ID())
	currToken, err := svc.Checker.GetTokenResolver().Resolve(c)
	if err != nil || currToken == nil {
		if err != nil {
			log.Println("resolve token failed:", err.Error())
		}
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}

	// 3.获取JWT token key
	tk, err := svc.TokenKey.GetTokenKey()
	log.Println("get token key succeed.")
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 4.校验token
	log.Println("found token,type:" + currToken.Type)
	claims, err := svc.Checker.Check(tk, currToken)
	if err != nil {
		log.Println("invalid access token:", err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 5.新建session，cookie，并将认证结果存入session之中
	err = svc.Session.SaveAuthorization(c, currToken, claims)
	if err != nil {
		log.Println("cannot save session: ", err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unauthorized"))
		return
	}
	// 6.token校验成功，将认证信息添加到当前请求头
	svc.SuccessHandler(c, currToken, claims)
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
	s, err := svc.Session.CreateState(c)
	if err != nil {
		log.Println("unable create state: " + err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unable create state"))
		return
	}
	// 将请求转发到OAuth2 authorize endpoint
	redirectUri = fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
		svc.OAuth2IssuerEndpoint, svc.ClientId, svc.Scope, s, svc.LoginCallbackEndpoint)
	log.Println("login handler, redirecting to: " + redirectUri)
	c.Redirect(http.StatusMovedPermanently, redirectUri)
}

func (svc *OAuth2Svc) TryRefreshToken(c *gin.Context) {
	go func() {
		sess := sessions.Default(c)
		tokenKey := session.TokenKey(sess.ID())
		detailsKey := session.DetailsKey(sess.ID())

		cacheToken := &oauth2.Token{}
		details := &oauth2.UserDetails{}
		err := svc.RedisCli.Get(context.Background(), tokenKey).Scan(cacheToken)
		if err != nil {
			log.Println("unable to get token from redis: " + err.Error())
			return
		}
		err = svc.RedisCli.Get(context.Background(), detailsKey).Scan(details)
		if err != nil {
			log.Println("unable to get details from redis: " + err.Error())
			return
		}

		if cacheToken.RefreshToken == "" {
			return
		}
		// 有效时间小于等于60s则刷新
		if ttl, err := svc.RedisCli.TTL(context.Background(), tokenKey).Result(); err == nil && ttl > 60 {
			return
		}
		token, err := svc.RefreshToken(cacheToken.RefreshToken)
		if err != nil {
			log.Panicf("unable to refresh token: " + err.Error())
			return
		}
		ses := sessions.Default(c)
		// 更新session之中token信息
		expire := time.Duration(token.ExpiresIn) * time.Second
		err = svc.RedisCli.SetEx(context.Background(), session.TokenKey(ses.ID()), token, expire).Err()
		if err != nil {
			log.Panicf("unable to save token to session: " + err.Error())
			return
		}
		err = svc.RedisCli.Expire(context.Background(), session.DetailsKey(ses.ID()), expire).Err()
		if err != nil {
			log.Panicf("unable to save details to session: " + err.Error())
			return
		}
	}()
}

// Callback OAuth2 authorize endpoint认证成功回调接口
func (svc *OAuth2Svc) Callback(c *gin.Context) {
	// 获取State
	state, err := svc.Session.GetState(c)
	b := err != nil
	if b || state == nil {
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
	token, err := svc.ExchangeAccessTokenByCode(code, svc.LoginCallbackEndpoint)
	if err != nil {
		log.Println("unable to exchange code for access token: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to exchange code for access token"))
		return
	}
	// 获取JWT 解析key
	keyBytes, err := svc.TokenKey.GetTokenKey()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("get token key failed"))
		return
	}
	// 解析token
	details, err := svc.Checker.Check(keyBytes, token)
	if err != nil {
		log.Println("decode token err: ", err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("decode token failed"))
		return
	}

	// 新建session，cookie并将认证信息存入session之中
	err = svc.Session.SaveAuthorization(c, token, details)
	if err != nil {
		log.Println("callback handler, unable to save access token to session: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to save access token to session"))
		return
	}
	sess := sessions.Default(c)
	log.Println("callback handle succeed, redirecting to: "+state.RedirectUri, "session id:"+sess.ID())
	// 将请求转发到原来的地址
	c.Redirect(http.StatusPermanentRedirect, state.RedirectUri)
}

func (svc *OAuth2Svc) Logout(c *gin.Context) {
	token, err := svc.Checker.GetTokenResolver().Resolve(c)
	if err != nil || token == nil {
		c.JSON(http.StatusForbidden, r.Failed("not found access token"))
		return
	}
	url := svc.OAuth2IssuerEndpoint + "/oauth2/logout"
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewBuffer(nil))
	if err != nil {
		c.JSON(http.StatusInternalServerError, r.Failed("create delete request failed"))
		return
	}
	req.Header.Set("Authorization", string(token.Type)+" "+token.AccessToken)
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

func successHandler(c *gin.Context, token *oauth2.Token, details *oauth2.UserDetails) {
	c.Header("X-Auth-Tenant-Id", strconv.FormatInt(int64(details.TenantId), 20))
	c.Header("X-Auth-User-Id", strconv.FormatInt(details.Id, 20))
	c.Header("X-Auth-User-Name", details.Username)
	c.Header("X-Auth-Role-Ids", Int64SliceToString(details.RoleIds))
	c.Header("X-Auth-Role-Types", Int64SliceToString(details.RoleTypes))
	c.Header("Authorization", token.AuthorizationHeader())
	c.JSON(http.StatusOK, r.Succeed("authenticated"))
}

func Int64SliceToString(arr []int64) string {
	strArr := make([]string, len(arr))
	for i, num := range arr {
		strArr[i] = strconv.FormatInt(num, 10) // 转为十进制字符串
	}
	return strings.Join(strArr, ",")
}
