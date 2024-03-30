package samples

import (
	"github.com/lucky-xin/xyz-common-go/sign"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"testing"
)

func TestSignRequest(t *testing.T) {
	appId := "f2aa0059a6e4f8bac775c4fd0afcc"
	appSecret := "125809f6819ANBgkqpiiG9w0BAQEFAASCwggE6AgEAAkEAl3cpw0oz"
	url := "http://127.0.0.1:6666/check"
	timestamp, s := sign.SignWithTimestamp(appSecret, "")
	byts, err := utils.Get(url, s, appId, timestamp)
	if err != nil {
		panic(err)
	}
	println(string(byts))
}
