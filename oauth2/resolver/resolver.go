package resolver

import (
	"context"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/session"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/utils"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	xresolver "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/redis/go-redis/v9"
	"log"
)

type Resolver struct {
	cli            redis.UniversalClient
	delegate       xresolver.TokenResolver
	paramTokenName string
	tokenTypes     []oauth2.TokenType
}

func (d Resolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d Resolver) Resolve(c *gin.Context) *oauth2.Token {
	// 尝试从请求头，请求参数之中获取token
	t := d.delegate.Resolve(c)
	if t != nil {
		return t
	}
	// 从session之中获取token
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	cache := d.cli.HGetAll(context.Background(), session.TokenKey(sess.ID())).Val()
	if cache == nil {
		return nil
	}
	return &oauth2.Token{
		Type:   oauth2.TokenType(strutil.ToString(cache["type"])),
		Value:  strutil.ToString(cache["value"]),
		Params: utils.ToMap(cache["params"], nil),
	}
}

func Create(cli redis.UniversalClient) *Resolver {
	paramTokenName := env.GetString("OAUTH2_URI_PARAM_TOKEN_NAME", "authz")
	array := env.GetStringArray("OAUTH2_TOKEN_TYPE", []string{"OAUTH2", "SIGN"})
	var tokenTypes []oauth2.TokenType
	for i := range array {
		item := array[i]
		tokenTypes = append(tokenTypes, oauth2.TokenType(item))
	}
	tokenResolver := xresolver.Create(paramTokenName, tokenTypes)
	return &Resolver{
		cli:            cli,
		paramTokenName: paramTokenName,
		tokenTypes:     tokenTypes,
		delegate:       tokenResolver,
	}
}
