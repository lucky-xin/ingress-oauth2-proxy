package samples

import (
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"io"
	"log"
	"net/http"
	"testing"
	"time"
)

type InMemoryEncryptionInfSvc struct {
	confs map[string]*types.EncryptionInf
}

func (svc *InMemoryEncryptionInfSvc) GetEncryptionInf(appId string) (*types.EncryptionInf, error) {
	inf := svc.confs[appId]
	if inf == nil {
		return nil, errors.New("not found config,app id:" + appId)
	}
	return inf, nil
}

func TestOAUth2SvrTest(t *testing.T) {
	confs := map[string]*types.EncryptionInf{
		"9c607513b605406497afc395b0xyz": {
			AppId:     "9c607513b605406497afc395b0xyz",
			AppSecret: "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAl3.lcx.xyz",
			TenantId:  1,
			Username:  "lcx",
			UserId:    1,
		},
		"9c607513b605406497afc395b011xyz": {
			AppId:     "9c607513b605406497afc395b0xyz",
			AppSecret: "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAl3xyz.xyz",
			TenantId:  1,
			Username:  "hahaha",
			UserId:    2,
		},
	}
	confSvc := &InMemoryEncryptionInfSvc{confs: confs}

	tk := "eyJraWQiOiJmY2Y2MDE4Ny0wOGE0LTQ4NGUtOTVmMS0wNzdhNDUzZWU3NjIiLCJhbGciOiJIUzUxMiJ9"

	gin.SetMode(env.GetString("GIN_MODE", gin.DebugMode))
	engine := gin.New()
	tokenResolver := resolver.NewDefaultTokenResolver("authz", []types.TokenType{types.SIGN})
	checker, err := authz.NewChecker(
		tokenResolver,
		authz.RestTokenKey,
		map[types.TokenType]types.Checker{
			types.OAUTH2: authz.NewTokenChecker([]string{"HS512"}, tokenResolver),
			types.SIGN:   authz.NewSignChecker(confSvc, tokenResolver),
		},
	)
	if err != nil {
		panic(err)
	}
	engine.GET("/oauth2/token-key", func(c *gin.Context) {
		// 校验数字签名
		reqToken := tokenResolver.Resolve(c)
		if reqToken != nil {
			_, err := checker.Check([]byte(tk), reqToken)
			if err != nil {
				c.JSON(http.StatusOK, r.Failed(err.Error()))
				return
			}
		}
		key := "B31F2A75FBF94099B31F2A75FBF94099" // 此处16|24|32个字符
		iv := "1234567890123456"
		encryptor := aescbc.Encryptor{Key: key, Iv: iv}
		re, err := encryptor.EncryptWithBase64([]byte(tk))
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		c.JSON(http.StatusOK, r.Succeed(re))
	}).GET("/oauth2/encryption-conf/app-id/:appId", func(c *gin.Context) {
		appId := c.Param("appId")
		// 查询DB获取配置信息
		conf, err := confSvc.GetEncryptionInf(appId)
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		c.JSON(http.StatusOK, r.Succeed(conf))
	}).GET("/oauth2/introspect", func(c *gin.Context) {
		claims, err := checker.CheckWithContext([]byte(tk), c)
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		c.JSON(http.StatusOK, r.Succeed(claims))
	}).POST("/oauth2/token", func(c *gin.Context) {
		jsonBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		var user XyzUser
		err = json.Unmarshal(jsonBytes, &user)
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		claims := &types.XyzClaims{
			Username: user.Username,
			UserId:   1,
			TenantId: 1,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Subject:   "xyz.com",
			},
		}
		token, err := utils.CreateToken([]byte(tk), claims)
		if err != nil {
			c.JSON(http.StatusOK, r.Failed(err.Error()))
			return
		}
		resp := map[string]interface {
		}{
			"access_token": token,
			"tenant_id":    1,
			"expires_in":   claims.ExpiresAt.Second() - claims.IssuedAt.Second(),
			"username":     user.Username,
		}
		c.JSON(http.StatusOK, r.Succeed(resp))
	})
	errc := make(chan error)
	restPort := env.GetString("SERVER_PORT", "6666")
	addr := ":" + restPort
	log.Println("listening on http://0.0.0.0:" + restPort)
	errc <- engine.Run(addr)
}
