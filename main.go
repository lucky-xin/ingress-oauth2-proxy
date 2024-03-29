package main

import (
	"fmt"
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
	// 基于redis的session配置
	sessionKeyPairs := env.GetString("OAUTH2_SESSION_KEY_PAIRS", "WWtkT05BPT0")
	store, err := session.NewRedisStore(auth2Svc.RedisCli, "session:ingress_oauth2_proxy:", []byte(sessionKeyPairs))
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
	engine.GET("/check", func(c *gin.Context) {
		auth2Svc.Check(c)
	}).
		// 登录API
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
