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

package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/pointer"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-go/text"
	xoauth2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"net/http"
	"time"
)

var (
	sessStateName  = "_state_"
	sessAuthzName  = "_principal_"
	stateFieldName = "state"
	MagicByte      = byte(9)
)

type Session struct {
	uriParamName string
	rcli         redis.UniversalClient
	stateExpr    time.Duration
	path         string
	domain       string
	sameSite     http.SameSite
	secure       bool
	httpOnly     bool
}

func Create(uriParamName string, rcli redis.UniversalClient) *Session {
	expire := env.GetInt64("OAUTH2_SESSION_STATE_EXPIRE_MS", 3*time.Minute.Milliseconds())
	return &Session{
		rcli:         rcli,
		uriParamName: uriParamName,
		stateExpr:    time.Duration(expire) * time.Millisecond,
		path:         env.GetString("OAUTH2_SESSION_PATH", "/"),
		domain:       env.GetString("OAUTH2_SESSION_DOMAIN", ""),
		sameSite:     http.SameSite(env.GetInt("OAUTH2_SESSION_SAME_SITE", int(http.SameSiteLaxMode))),
		secure:       env.GetBool("OAUTH2_SESSION_SECURE", true),
		httpOnly:     env.GetBool("OAUTH2_SESSION_HTTP_ONLY", true),
	}
}

func (svc *Session) SaveAuthorization(c *gin.Context, token *xoauth2.Token, claims *xoauth2.UserDetails) (err error) {
	svc.DeleteState(c)
	ses, err := svc.Create(c, sessAuthzName, token, 12*time.Hour)
	if err != nil {
		return
	}
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	err = svc.rcli.Set(context.Background(), DetailsKey(ses.ID()), claims, expire).Err()
	svc.SaveAuthzToCookie(c, claims)
	return
}

func (svc *Session) Create(c *gin.Context, key, val interface{}, expire time.Duration) (s sessions.Session, err error) {
	s = sessions.Default(c)
	log.Println("Creating ses id:", s.ID())

	s.Options(sessions.Options{
		Domain:   svc.domain,
		Path:     svc.path,
		MaxAge:   int(expire.Seconds()),
		Secure:   svc.secure,
		HttpOnly: svc.httpOnly,
		SameSite: svc.sameSite,
	})
	s.Set(key, val)
	// 必须先执行Session.Save()才能拿到Session id
	err = s.Save()
	log.Println("Created ses id:", s.ID())
	return
}

func (svc *Session) Get(c *gin.Context, key string) interface{} {
	s := sessions.Default(c)
	log.Println("Get ses id:", s.ID())
	return s.Get(key)
}

func (svc *Session) GetToken(c *gin.Context) (token *xoauth2.Token) {
	t := svc.Get(c, sessAuthzName)
	if t == nil {
		return
	}
	if m, ok := t.(map[string]interface{}); ok {
		params := map[string]string{}
		if m1, o := m["params"].(map[string]string); o {
			params = m1
		}
		token = &xoauth2.Token{
			AccessToken:  strutil.ToString(m["access_token"]),
			RefreshToken: strutil.ToString(m["refresh_token"]),
			Scope:        strutil.ToString(m["scope"]),
			Type:         xoauth2.TokenType(strutil.ToString(m["type"])),
			ExpiresIn:    strutil.ToInt(strutil.ToString(m["expires_at"]), 0),
			Params:       params,
		}
	}
	return
}

func (svc *Session) SaveAuthzToCookie(c *gin.Context, claims *xoauth2.UserDetails) {
	inf := map[string]interface{}{
		"uid":        claims.Id,
		"tid":        claims.TenantId,
		"uname":      claims.Username,
		"expires_at": claims.ExpiresAt.Time.UnixMilli(),
	}
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	es := int(expire.Seconds())
	for k, v := range inf {
		c.SetCookie(k, strutil.ToString(v), es, svc.path, svc.domain, svc.secure, svc.httpOnly)
	}
}

func (svc *Session) GetState(c *gin.Context) (inf *oauth2.StateInf, err error) {
	sess := sessions.Default(c)
	log.Println("GetState...", sess.ID())
	val := sess.Get(sessStateName)
	if val == nil {
		err = errors.New("not found state in session")
		return
	}
	var stateCache, stateUrl string
	switch val.(type) {
	case map[string]interface{}:
		cache := val.(map[string]interface{})
		if sc, ok := cache["value"].(string); ok {
			stateCache = sc
		}
	case string:
		stateCache = val.(string)
	}

	stateUrl = c.Query(stateFieldName)
	if stateUrl != stateCache {
		err = errors.New("invalid state in session")
		return
	}
	inf = &oauth2.StateInf{}
	err = svc.rcli.Get(context.Background(), Key(stateCache)).Scan(inf)
	return
}

func (svc *Session) CreateState(c *gin.Context) (state string, err error) {
	ru := c.Query(svc.uriParamName)
	if ru == "" {
		return "", errors.New("not found redirect uri in query param:" + svc.uriParamName)
	}
	b1, err := createRandomBytes(24)
	if err != nil {
		return
	}
	b2, err := createRandomBytes(4)
	if err != nil {
		return
	}
	block := text.Block{
		MagicByte: pointer.Ptr(MagicByte),
		Segments: []*text.Segment{
			{Length: len(b1), Bytes: b1},
			{Length: len(b2), Bytes: b2},
		}}
	buff, err := block.ToBuffer()
	if err != nil {
		return
	}
	state = base64.URLEncoding.EncodeToString(buff.Bytes())
	inf := oauth2.StateInf{Value: state, RedirectUri: ru}
	byts, err := json.Marshal(inf)
	if err != nil {
		return
	}
	_, err = svc.rcli.SetEx(context.Background(), Key(state), string(byts), svc.stateExpr).Result()
	if err != nil {
		return
	}
	_, err = svc.Create(c, sessStateName, state, svc.stateExpr)
	return state, err
}

func (svc *Session) DeleteState(c *gin.Context) {
	sess := sessions.Default(c)
	sess.Delete(sessStateName)
}

func createRandomBytes(len int) (byts []byte, err error) {
	b := make([]byte, len)
	if _, err = io.ReadFull(rand.Reader, b); err != nil {
		return
	}
	byts = b
	return
}

func DetailsKey(suffix string) string {
	return oauth2.SessionName + ":details:" + suffix
}

func Key(state string) string {
	return oauth2.SessionName + ":state:" + state
}
