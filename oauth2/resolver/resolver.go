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

package resolver

import (
	"context"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/session"
	"github.com/lucky-xin/xyz-common-go/env"
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

func (d Resolver) Resolve(c *gin.Context) (t *oauth2.Token, err error) {
	// 尝试从请求头，请求参数之中获取token
	t, err = d.delegate.Resolve(c)
	if err != nil {
		return
	}
	// 从session之中获取token
	sess := sessions.Default(c)
	log.Println("try get token from session, session id:" + sess.ID())
	err = d.cli.HGetAll(context.Background(), session.TokenKey(sess.ID())).Scan(t)
	return
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
