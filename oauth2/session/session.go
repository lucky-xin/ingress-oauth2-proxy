package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"io"
	"log"
	"net/http"
	"time"
)

var (
	stateFieldName = "state"
)

type Session struct {
	SessionDomain string
	UriParamName  string
	Expire        time.Duration
}

func (svc *Session) Create(c *gin.Context) (string, error) {
	sess := sessions.Default(c)
	log.Println("create session id:" + sess.ID())
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	sess.Options(sessions.Options{
		Domain:   svc.SessionDomain,
		Path:     "/",
		MaxAge:   int(svc.Expiration().Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	sess.Set(stateFieldName, map[string]interface{}{
		svc.UriParamName: c.Param(svc.UriParamName),
		"value":          state,
	})
	return state, sess.Save()
}

func (svc *Session) Get(c *gin.Context) (*oauth2.StateInf, error) {
	state := c.Query("state")
	sess := sessions.Default(c)
	val := sess.Get(stateFieldName)
	if val == nil {
		return nil, errors.New("not found state in session")
	}
	switch val.(type) {
	case map[string]interface{}:
		cache := val.(map[string]interface{})
		if state == cache["value"] {
			return &oauth2.StateInf{Value: cache["value"].(string), RedirectUri: cache[svc.UriParamName].(string)}, nil
		}
	}

	return nil, errors.New("not found state in session")
}
func (svc *Session) Expiration() time.Duration {
	return svc.Expire
}

func (svc *Session) RedirectUriParamName() string {
	return svc.UriParamName
}

func TokenKey(suffix string) string {
	return "session_token:" + suffix
}
