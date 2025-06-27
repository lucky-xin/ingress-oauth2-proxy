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

package main

import (
	"fmt"
	"github.com/bsm/redislock"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/session"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2/svc"
	"github.com/lucky-xin/xyz-common-go/env"
	"log"
	"net/http"
)

// errHandler 统一500错误处理函数
func errHandler(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			//打印错误堆栈信息
			msg, _ := fmt.Printf("%v", err)
			log.Printf("panic: %v\n", err)
			c.HTML(http.StatusOK, "500.html", gin.H{
				"title": "500",
				"error": msg,
			})
		}
	}()
	c.Next()
}

func main() {
	auth2Svc, err := svc.Create()
	if err != nil {
		panic(err)
	}
	gin.SetMode(env.GetString("GIN_MODE", gin.DebugMode))
	engine := gin.New()
	engine.Group("/health").GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	locker := redislock.New(auth2Svc.RedisCli)
	// 基于redis的session配置
	store, err := session.NewRedisStore(auth2Svc.RedisCli, locker, oauth2.SessionName+":session:")
	if err != nil {
		panic(err)
	}
	engine.Use(errHandler, sessions.Sessions(oauth2.SessionName, store))
	// 加载静态资源
	engine.StaticFS("/static", http.Dir("./static"))
	// 加载模板文件
	engine.LoadHTMLGlob("templates/*.html")
	engine.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusOK, "404.html", gin.H{
			"title": "404",
		})
	})
	// ingress-oauth2-proxy token校验API，每次请求都会进行拦截，验证当前session是否有验证信息
	engine.
		GET("/check", func(c *gin.Context) {
			auth2Svc.Check(c)
		}).
		GET("/login", func(c *gin.Context) {
			auth2Svc.Login(c)
		}).
		// OAuth2 authorize endpoint回调API
		GET("/callback", func(c *gin.Context) {
			auth2Svc.Callback(c)
		}).
		// 登出API
		GET("/logout", func(c *gin.Context) {
			auth2Svc.Logout(c)
		})

	errc := make(chan error)
	restPort := env.GetString("SERVER_PORT", "6666")
	addr := ":" + restPort
	log.Println("listening on http://0.0.0.0:" + restPort)
	errc <- engine.Run(addr)
}
