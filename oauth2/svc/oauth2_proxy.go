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
	clientId              string
	scope                 string
	basicAuthzHeader      string
	oauth2IssuerEndpoint  string
	checker               authz.Checker
	tokenKey              authz.TokenKeySvc
	loginCallbackEndpoint string
	redirectUriParamName  string
	sessionDomain         string
	successHandler        SuccessHandler
	session               *session.Session
	RedisCli              redis.UniversalClient
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
		oauth2IssuerEndpoint:  issuerEndpoint,
		scope:                 os.Getenv("OAUTH2_SCOPE"),
		basicAuthzHeader:      oauth2.CreateBasicAuth(clientId, os.Getenv("OAUTH2_CLIENT_SECRET")),
		clientId:              clientId,
		RedisCli:              client,
		loginCallbackEndpoint: fmt.Sprintf("%s/callback", oauth2ProxyEndpoint),
		redirectUriParamName:  ruParamName,
		checker:               checker,
		session:               session.Create(ruParamName, client),
		tokenKey:              key.CreateWithEnv(),
		successHandler:        successHandler,
	}
	return auth2Svc, nil
}

// ExchangeAccessTokenByCode get access token by code
func (svc *OAuth2Svc) ExchangeAccessTokenByCode(code, redirectUri string) (token *oauth2.Token, err error) {
	// http:127.0.0.1:3000/oauth/token?scope=read&grant_type=authorization_code&redirect_uri=
	//https://www.pistonidata.com&code=
	reader := strings.NewReader(
		fmt.Sprintf("scope=%s&grant_type=authorization_code&redirect_uri=%s&code=%s",
			svc.scope, redirectUri, code,
		),
	)
	accessTokenEndpoint := svc.oauth2IssuerEndpoint + "/oauth/token"
	req, err := http.NewRequest(http.MethodPost, accessTokenEndpoint, reader)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", svc.basicAuthzHeader)
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
	accessTokenEndpoint := svc.oauth2IssuerEndpoint + "/oauth/token"
	formData := url.Values{}
	formData.Set("scope", svc.scope)
	formData.Set("grant_type", "refresh_token")
	formData.Set("refresh_token", refreshToken)
	reader := strings.NewReader(formData.Encode())
	if req, err := http.NewRequest(http.MethodPost, accessTokenEndpoint, reader); err != nil {
		return nil, err
	} else {
		req.Header.Set("Authorization", svc.basicAuthzHeader)
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
		cacheToken := svc.session.GetToken(c)
		details := &oauth2.UserDetails{}
		detailsKey := session.DetailsKey(sess.ID())

		err := svc.RedisCli.Get(context.Background(), detailsKey).Scan(details)
		if err == nil && cacheToken != nil && details != nil {
			svc.TryRefreshToken(c)
			// session 有认证信息直接返回
			svc.successHandler(c, cacheToken, details)
			return
		}
	}

	// 2.尝试从请求头，URL参数之中获取token
	currToken, err := svc.checker.GetTokenResolver().Resolve(c)
	if err != nil || currToken == nil {
		if err != nil {
			log.Println("resolve token failed:", err.Error())
		}
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}

	// 3.获取JWT token key
	tk, err := svc.tokenKey.GetTokenKey()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 4.校验token
	claims, err := svc.checker.Check(tk, currToken)
	if err != nil {
		log.Println("invalid access token:", err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unauthorized"))
		return
	}
	// 5.新建session，cookie，并将认证结果存入session之中
	err = svc.session.SaveAuthorization(c, currToken, claims)
	if err != nil {
		log.Println("cannot save session: ", err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unauthorized"))
		return
	}
	// 6.token校验成功，将认证信息添加到当前请求头
	svc.successHandler(c, currToken, claims)
	return
}

// Login 登录，基于OAuth2 authorize endpoint实现，获取原始访问地址redirectUri保存到Redis缓存之中，认证成功之后
// 从Redis之中获取redirectUri，再将请求转发到该地址
func (svc *OAuth2Svc) Login(c *gin.Context) {
	// 新建State，并将redirectUri保存
	s, err := svc.session.CreateState(c)
	if err != nil {
		log.Println("unable create state: " + err.Error())
		c.JSON(http.StatusInternalServerError, r.Failed("unable create state"))
		return
	}
	// 将请求转发到OAuth2 authorize endpoint
	redirectUri := fmt.Sprintf(
		"%s/oauth2/authorize?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s",
		svc.oauth2IssuerEndpoint, svc.clientId, svc.scope, s, svc.loginCallbackEndpoint)
	log.Println("login handler, redirecting to: " + redirectUri)
	c.Redirect(http.StatusMovedPermanently, redirectUri)
}

func (svc *OAuth2Svc) TryRefreshToken(c *gin.Context) {
	go func() {
		sess := sessions.Default(c)
		cacheToken := svc.session.GetToken(c)
		if cacheToken == nil || cacheToken.RefreshToken == "" {
			return
		}
		detailsKey := session.DetailsKey(sess.ID())
		details := &oauth2.UserDetails{}
		err := svc.RedisCli.Get(context.Background(), detailsKey).Scan(details)
		if err != nil {
			log.Println("unable to get details from redis: " + err.Error())
			return
		}
		// 有效时间小于等于2分钟则刷新
		notExpired := details.ExpiresAt.Time.Sub(details.IssuedAt.Time).Minutes() > 2
		if notExpired {
			return
		}
		token, err := svc.RefreshToken(cacheToken.RefreshToken)
		if err != nil {
			log.Panicf("unable to refresh token: " + err.Error())
			return
		}

		// 3.获取JWT token key
		tk, err := svc.tokenKey.GetTokenKey()
		if err != nil {
			log.Println("TryRefreshToken, get token key error:" + err.Error())
			return
		}
		// 4.校验token
		claims, err := svc.checker.Check(tk, token)
		if err != nil {
			log.Println("TryRefreshToken, invalid access token:", err.Error())
			return
		}
		// 5.新建session，cookie，并将认证结果存入session之中
		err = svc.session.SaveAuthorization(c, token, claims)
		if err != nil {
			log.Println("TryRefreshToken, cannot save session: ", err.Error())
			return
		}
	}()
}

// Callback OAuth2 authorize endpoint认证成功回调接口
func (svc *OAuth2Svc) Callback(c *gin.Context) {
	// 获取State
	state, err := svc.session.GetState(c)
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
	token, err := svc.ExchangeAccessTokenByCode(code, svc.loginCallbackEndpoint)
	if err != nil {
		log.Println("unable to exchange code for access token: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to exchange code for access token"))
		return
	}
	// 获取JWT 解析key
	keyBytes, err := svc.tokenKey.GetTokenKey()
	if err != nil {
		log.Println("get token key error:" + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("get token key failed"))
		return
	}
	// 解析token
	details, err := svc.checker.Check(keyBytes, token)
	if err != nil {
		log.Println("decode token err: ", err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("decode token failed"))
		return
	}

	// 新建session，cookie并将认证信息存入session之中
	err = svc.session.SaveAuthorization(c, token, details)
	if err != nil {
		log.Println("callback handler, unable to save access token to session: " + err.Error())
		c.JSON(http.StatusUnauthorized, r.Failed("unable to save access token to session"))
		return
	}
	svc.session.DeleteState(c, state.Value)
	sess := sessions.Default(c)
	log.Println("callback handle succeed, redirecting to: "+state.RedirectUri, "session id:"+sess.ID())
	// 将请求转发到原来的地址
	c.Redirect(http.StatusPermanentRedirect, state.RedirectUri)
}

func (svc *OAuth2Svc) Logout(c *gin.Context) {
	token, err := svc.checker.GetTokenResolver().Resolve(c)
	if err != nil || token == nil {
		c.JSON(http.StatusForbidden, r.Failed("not found access token"))
		return
	}
	logoutUrl := svc.oauth2IssuerEndpoint + "/oauth2/logout"
	req, err := http.NewRequest(http.MethodDelete, logoutUrl, bytes.NewBuffer(nil))
	if err != nil {
		c.JSON(http.StatusInternalServerError, r.Failed("create delete request failed"))
		return
	}
	req.Header.Set("Authorization", token.AuthorizationHeader())
	_, err = httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, r.Failed("send delete request failed"))
		return
	}
	sess := sessions.Default(c)
	sess.Clear()

	redirectUri := c.Query(svc.redirectUriParamName)
	if redirectUri == "" {
		return
	}
	c.Redirect(http.StatusFound, redirectUri)
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
