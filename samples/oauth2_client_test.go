package samples

import (
	"bytes"
	"encoding/json"
	"github.com/lucky-xin/xyz-common-go/r"
	aescbc "github.com/lucky-xin/xyz-common-go/security/aes.cbc"
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	resolver2 "github.com/lucky-xin/xyz-common-oauth2-go/oauth2/resolver"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"io"
	"net/http"
	"testing"
)

func TestOAUth2CliTest(tet *testing.T) {
	appId := "9c607513b605406497afc395b011xyz"
	appSecret := "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAl3xyz.xyz"
	// 获取token key
	//生成数字签名
	var timestamp, sgn string
	if appId != "" && appSecret != "" {
		timestamp, sgn = sign.SignWithTimestamp(appSecret, "")
	}
	//获取token key
	client := &http.Client{}
	url := "http://127.0.0.1:6666/oauth2/token-key"
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Signature "+sgn)
	req.Header.Set("App-Id", appId)
	req.Header.Set("Timestamp", timestamp)
	resp, err := client.Do(req)

	if err != nil {
		panic(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	var tokenKeyResp r.Resp[string]
	byts, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(byts, &tokenKeyResp)
	if err != nil {
		panic(err)
	}
	println("orig token key->", tokenKeyResp.Data())

	deTk := tokenKeyResp.Data()
	aesKey := "B31F2A75FBF94099B31F2A75FBF94099" // 此处16|24|32个字符
	aesIv := "1234567890123456"
	encryptor := aescbc.Encryptor{Key: aesKey, Iv: aesIv}
	tk, err := encryptor.Decrypt(deTk)
	if err != nil {
		panic(err)
	}
	println("plaintext token key->", string(tk))

	// 获取token
	url = "http://127.0.0.1:6666/oauth2/token"
	params := map[string]interface{}{
		"username": "chaoxin.lu",
		"password": "************",
	}

	jsonBytes, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	req, err = http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		panic(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	var tokenResp r.Resp[XyzOAuth2Token]
	byts, err = io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(byts, &tokenResp)
	if err != nil {
		panic(err)
	}
	println("access token ->", tokenResp.Data().AccessToken)

	// 解析token
	t := &types.Token{Type: types.OAUTH2, Value: tokenResp.Data().AccessToken}

	resolver := resolver2.NewDefaultTokenResolver("oauthz", []types.TokenType{types.OAUTH2})
	checker, err := authz.NewChecker(
		resolver,
		authz.RestTokenKey,
		map[types.TokenType]types.Checker{
			types.OAUTH2: authz.NewTokenChecker([]string{"HS512"}, resolver),
			types.SIGN:   authz.NewRestSignChecker("http://127.0.0.1:6666/oauth2/encryption-conf/app-id", resolver),
		},
	)
	if err != nil {
		panic(err)
	}
	deClaims, err := checker.Check(tk, t)
	if err != nil {
		panic(err)
	}
	println(deClaims.UserId)
	println(deClaims.Username)
}
