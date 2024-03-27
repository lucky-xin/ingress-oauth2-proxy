package resolver

import (
	"context"
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	xresolver "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/redis/go-redis/v9"
	"log"
	"reflect"
	"time"
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
	t := d.delegate.Resolve(c)
	if t != nil {
		return t
	}
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	cache := d.cli.HGetAll(context.Background(), sessionTokenKey(sess.ID())).Val()
	if cache == nil {
		return nil
	}
	return &oauth2.Token{
		Type:   oauth2.TokenType(strutil.ToString(cache["type"])),
		Value:  strutil.ToString(cache["value"]),
		Params: toMap(cache["params"], nil),
	}
}
func (d Resolver) Save(
	c *gin.Context,
	t *oauth2.Token,
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

func (d Resolver) Del(c *gin.Context) {
	sess := sessions.Default(c)
	d.cli.Del(context.Background(), sessionTokenKey(sess.ID()))
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
