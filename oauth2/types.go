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

/*
 * @Last Modified by: luchaoxin
 * @Last Modified time: 2024-01-07 14:06:04
 */

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
