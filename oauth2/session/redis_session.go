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

func (svc *Session) SaveAuthorization(c *gin.Context, t *xoauth2.Token, claims *xoauth2.XyzClaims) (err error) {
	expire := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	// 必须先执行Session.Save()才能拿到Session id
	ses, err := svc.CreateSession(c, expire, sessUserInfoName, map[string]interface{}{
		"uid":   claims.UserId,
		"tid":   claims.TenantId,
		"uname": claims.Username,
	})
	if ses.Get(sessStateName) != nil {
		ses.Delete(sessStateName)
	}
	tokenKey := TokenKey(ses.ID())
	result, err := svc.rcli.Exists(context.Background(), tokenKey).Result()
	if result != 0 || err != nil {
		return
	}
	// 不保存params信息
	err = svc.rcli.HSet(context.Background(), tokenKey, map[string]interface{}{
		"tid":   t.Tid,
		"uid":   t.Uid,
		"uname": t.Uname,
		"type":  string(t.Type),
		"value": t.Value,
	}).Err()
	if err != nil {
		return
	}
	err = svc.rcli.Expire(context.Background(), tokenKey, expire).Err()
	return
}

func (svc *Session) CreateSession(c *gin.Context, expire time.Duration, key, val interface{}) (s sessions.Session, err error) {
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

func (svc *Session) GetState(c *gin.Context) (*oauth2.StateInf, error) {
	sess := sessions.Default(c)
	val := sess.Get(sessStateName)
	if val == nil {
		return nil, errors.New("not found state in session")
	}
	switch val.(type) {
	case map[string]interface{}:
		cache := val.(map[string]interface{})
		if c.Query(stateFieldName) == cache["value"] {
			return &oauth2.StateInf{Value: cache["value"].(string), RedirectUri: cache[svc.uriParamName].(string)}, nil
		}
	}
	return nil, errors.New("invalid state in session")
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
	state = base64.StdEncoding.EncodeToString(buff.Bytes())
	ex := svc.rcli.SetEx(context.Background(), Key(state), ru, svc.stateExpr)
	err = ex.Err()
	if err != nil {
		return
	}
	_, err = svc.CreateSession(c, svc.stateExpr, sessStateName, state)
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
	return "session_token:" + suffix
}

func Key(state string) string {
	return "oauth2_proxy:state:" + state
}
