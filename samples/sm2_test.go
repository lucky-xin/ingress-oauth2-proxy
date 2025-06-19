package samples

import (
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestSm2(t *testing.T) {
	text := "国密算法SM2"
	publicKey := "04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266"
	privateKey := "90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6"
	sm2e, err := encryption.NewSM2(publicKey, privateKey)
	if err != nil {
		t.Error(err)
	}
	mode := sm2.C1C3C2
	encryptText, err := sm2e.Encrypt(text, mode)
	if err != nil {
		t.Error(err)
	}
	println(encryptText)
	decrypt, err := sm2e.Decrypt(encryptText, mode)
	if err != nil {
		t.Error(err)
	}

	println(decrypt)
	cipherText := "04b89e21ff8434dc55f0f60563c86a976234bf6fc2ccb2d4b7fb9948b52dc5319efd2619faf5c289c2ea638cf33523b3fbf9df41dd115f1edec5d9a9f922d754e1bc30e3368265d4728bf3e0d5473d2d96b0d9e498e5cbcaaef179f45bd52e50af0155ef410651f47b238593817eb8ed"
	decrypt, err = sm2e.Decrypt([]byte(cipherText), mode)
	if err != nil {
		t.Error(err)
	}
	println(decrypt)
}
