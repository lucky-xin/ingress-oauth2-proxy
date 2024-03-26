package xyz

import (
	"context"
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/redis/go-redis/v9"
	"log"
	"reflect"
	"strings"
	"time"
)

type OAuth2ProxyTokenResolver struct {
	cli            redis.UniversalClient
	paramTokenName string
	tokenType      types.TokenType
}

func (d OAuth2ProxyTokenResolver) UriParamTokenName() string {
	return d.paramTokenName
}

func (d OAuth2ProxyTokenResolver) TokenType() types.TokenType {
	return d.tokenType
}

func (d OAuth2ProxyTokenResolver) Save(
	c *gin.Context,
	t *types.Token,
	expire time.Duration) error {
	sess := sessions.Default(c)
	tokenKey := sessionTokenKey(sess.ID())
	result := d.cli.Exists(context.Background(), tokenKey).Val()
	if result != 0 {
		return nil
	}
	values := map[string]string{
		"type":  string(t.Type),
		"value": t.Value,
	}
	if t.Params != nil {
		marshal, err := json.Marshal(t.Params)
		if err != nil {
			return err
		}
		values["params"] = string(marshal)
	}
	err := d.cli.HMSet(context.Background(), tokenKey, values).Err()
	if err != nil {
		return err
	}
	return d.cli.Expire(context.Background(), tokenKey, expire).Err()
}

func sessionTokenKey(suffix string) string {
	return "session_token:" + suffix
}

func (d OAuth2ProxyTokenResolver) Del(c *gin.Context) {
	sess := sessions.Default(c)
	d.cli.Del(context.Background(), sessionTokenKey(sess.ID()))
}

func (d OAuth2ProxyTokenResolver) Resolve(c *gin.Context) *types.Token {
	prefixOAuth2 := d.tokenType
	authorization := c.GetHeader("Authorization")
	if authorization != "" {
		log.Print("access token from header")
		return &types.Token{Type: prefixOAuth2, Value: strings.TrimSpace(authorization[len(string(prefixOAuth2)):])}
	}

	token := c.Query(d.paramTokenName)
	if token != "" {
		log.Print("access token from query")
		tmp := strings.TrimSpace(token)
		split := strings.Split(tmp, " ")
		if len(split) == 2 {
			return &types.Token{Type: types.TokenType(strings.TrimSpace(split[0])), Value: strings.TrimSpace(split[1])}
		}
		return &types.Token{Type: types.OAUTH2, Value: strings.TrimSpace(split[0])}
	}
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	cache := d.cli.HGetAll(context.Background(), sessionTokenKey(sess.ID())).Val()
	if cache == nil {
		return nil
	}
	return &types.Token{
		Type:   types.TokenType(strutil.ToString(cache["type"])),
		Value:  strutil.ToString(cache["value"]),
		Params: toMap(cache["params"], nil),
	}
}

func toMap(val interface{}, defaultVal map[string]interface{}) map[string]interface{} {
	if val == nil {
		return defaultVal
	}
	kind := reflect.TypeOf(val).Kind()
	if kind == reflect.Map {
		return val.(map[string]interface{})
	}
	return defaultVal
}

func NewTokenResolver(cli redis.UniversalClient) *OAuth2ProxyTokenResolver {
	return &OAuth2ProxyTokenResolver{
		cli:            cli,
		paramTokenName: env.GetString("OAUTH2_URI_PARAM_TOKEN_NAME", "authz"),
		tokenType:      types.TokenType(env.GetString("OAUTH2_TOKEN_TYPE", "OAuth2")),
	}
}
