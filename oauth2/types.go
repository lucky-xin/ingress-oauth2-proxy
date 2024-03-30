package oauth2

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	xoauth2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"time"
)

var (
	SessionName = "oauth2_proxy"
)

type TokenResp struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data TokenInf `json:"data"`
}

type TokenInf struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type StateInf struct {
	Value       string `json:"value"`
	RedirectUri string `json:"ru"`
}

type Session interface {
	SaveAuthorization(c *gin.Context, t *xoauth2.Token, claims *xoauth2.XyzClaims) (err error)

	CreateSession(c *gin.Context, expire time.Duration, key, val interface{}) (s sessions.Session, err error)

	RedirectUriParamName() string

	GetState(c *gin.Context) (*StateInf, error)

	CreateState(c *gin.Context) (s string, err error)
}
