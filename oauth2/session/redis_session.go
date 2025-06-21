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
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/pointer"
	"github.com/lucky-xin/xyz-common-go/text"
	xoauth2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"time"
)

var (
	sessStateName    = "_state_"
	sessUserInfoName = "_principal_"
	stateFieldName   = "state"
	MagicByte        = byte(9)
)

type Session struct {
	sessionDomain string
	uriParamName  string
	rcli          redis.UniversalClient
	stateExpr     time.Duration
}

func Create(sessionDomain, uriParamName string, stateExpr time.Duration, rcli redis.UniversalClient) *Session {
	return &Session{
		sessionDomain: sessionDomain, rcli: rcli, uriParamName: uriParamName, stateExpr: stateExpr,
	}
}

func (svc *Session) SaveAuthorization(c *gin.Context, t *xoauth2.Token, claims *xoauth2.UserDetails) (err error) {
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	// 必须先执行Session.Save()才能拿到Session id
	ses, err := svc.CreateSession(c, sessUserInfoName, map[string]interface{}{
		"uid":   claims.Id,
		"tid":   claims.TenantId,
		"uname": claims.Username,
	}, expire)
	if err != nil {
		return
	}
	if ses.Get(sessStateName) != nil {
		ses.Delete(sessStateName)
	}
	// 不保存params信息
	err = svc.rcli.Set(context.Background(), TokenKey(ses.ID()), t, expire).Err()
	if err != nil {
		return
	}
	err = svc.rcli.Set(context.Background(), DetailsKey(ses.ID()), claims, RandomDuration(expire, expire*2)).Err()
	return
}

func (svc *Session) CreateSession(c *gin.Context, key, val interface{}, expire time.Duration) (s sessions.Session, err error) {
	s = sessions.Default(c)
	log.Println("Creating ses... id:", s.ID())
	s.Options(sessions.Options{
		Domain:   svc.sessionDomain,
		Path:     env.GetString("OAUTH2_SESSION_PATH", "/"),
		MaxAge:   int(expire.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	s.Set(key, val)
	// 必须先执行Session.Save()才能拿到Session id
	err = s.Save()
	log.Println("Created ses id:", s.ID())
	return
}

func (svc *Session) RedirectUriParamName() string {
	return svc.uriParamName
}

func (svc *Session) GetState(c *gin.Context) (inf *oauth2.StateInf, err error) {
	sess := sessions.Default(c)
	val := sess.Get(sessStateName)
	if val == nil {
		err = errors.New("not found state in session")
		return
	}
	var ru, stateCache, stateUrl string
	switch val.(type) {
	case map[string]interface{}:
		cache := val.(map[string]interface{})
		stateCache = cache["value"].(string)
	case string:
		stateCache = val.(string)
	}

	stateUrl = c.Query(stateFieldName)
	log.Println("cache state is:" + stateCache)
	log.Println("url   state is:" + stateUrl)
	if stateUrl != stateCache {
		err = errors.New("invalid state in session")
		return
	}
	ru, err = svc.rcli.Get(context.Background(), Key(stateCache)).Result()
	if err != nil {
		return
	}
	inf = &oauth2.StateInf{Value: stateCache, RedirectUri: ru}
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
	_, err = svc.rcli.SetEx(context.Background(), Key(state), ru, svc.stateExpr).Result()
	if err != nil {
		return
	}
	_, err = svc.CreateSession(c, sessStateName, state, svc.stateExpr)
	return state, err
}

func createRandomBytes(len int) (byts []byte, err error) {
	b := make([]byte, len)
	if _, err = io.ReadFull(rand.Reader, b); err != nil {
		return
	}
	byts = b
	return
}

func TokenKey(suffix string) string {
	return oauth2.SessionName + ":token:" + suffix
}

func DetailsKey(suffix string) string {
	return oauth2.SessionName + ":details:" + suffix
}

func Key(state string) string {
	return oauth2.SessionName + ":state:" + state
}

// RandomDuration 生成 min ~ max 之间的随机 Duration
func RandomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(mrand.Int63n(int64(max-min)))
}
