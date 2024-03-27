package oauth2

import (
	"github.com/gin-gonic/gin"
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

type State interface {
	Create(c *gin.Context) (string, error)
	Get(c *gin.Context) (*StateInf, error)
	Expiration() time.Duration
	RedirectUriParamName() string
}
