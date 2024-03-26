package samples

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/authz"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/types"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2/utils"
	"testing"
	"time"
)

func getKeyBytes(key string) []byte {
	keyBytes := []byte(key)
	switch l := len(keyBytes); {
	case l < 16:
		keyBytes = append(keyBytes, make([]byte, 16-l)...)
	case l > 16:
		keyBytes = keyBytes[:16]
	}
	return keyBytes
}

func doEncrypt(key string, origData []byte) ([]byte, error) {
	keyBytes := getKeyBytes(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, keyBytes[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func doDecrypt(key, crypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AESEncrypt(key string, val string) ([]byte, error) {
	origData := []byte(val)
	crypted, err := doEncrypt(key, origData)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

func AESDecrypt(key, val []byte) ([]byte, error) {
	origData, err := doDecrypt(key, val)
	if err != nil {
		return nil, err
	}
	return origData, nil
}

func TestExtractToken(test *testing.T) {
	tk := "eyJraWQiOiJmY2Y2MDE4Ny0wOGE0LTQ4NGUtOTVmMS0wNzdhNDUzZWU3NjIiLCJhbGciOiJIUzUxMiJ9"
	claims := &types.XyzClaims{
		Username: "chaoxin.lu",
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
		panic(err)
	}
	println(token)
	checker := authz.NewDefaultChecker()
	t := &types.Token{Type: types.OAUTH2, Value: token}
	deClaims, err := checker.Check([]byte(tk), t)
	if err != nil {
		panic(err)
	}
	println(deClaims.UserId)
}
