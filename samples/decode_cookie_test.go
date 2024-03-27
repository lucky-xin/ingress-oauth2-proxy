package samples

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/securecookie"
	"github.com/lucky-xin/xyz-common-go/strutil"
	"github.com/lucky-xin/xyz-common-oauth2-go/oauth2"
	"log"
	"reflect"
	"strings"
	"testing"
)

func TestSerToken(t *testing.T) {
	token := oauth2.Token{
		Type:   oauth2.OAUTH2,
		Value:  "kscjlkjaslhclkjalkjlsjllk",
		Params: nil,
	}
	b, _ := json.Marshal(token)
	println(string(b))
	m := make(map[string]interface{})
	_ = json.Unmarshal(b, &m)
	println(m)

	tmp := toMap(m, make(map[string]interface{}))

	tt := strutil.ToString(tmp["type"])
	if tt != "" {
		ot := &oauth2.Token{
			Type:   oauth2.TokenType(tt),
			Value:  strings.TrimSpace(strutil.ToString(tmp["value"])),
			Params: toMap(tmp["params"], nil),
		}
		println(ot.Value)
	}
}

func TestArray(t *testing.T) {
	linesText := "30eab827de40b3babcc95f253a4653242df2b676 172.28.167.219:6379@16379 master - 0 1693819612757 3 connected 10923-16383\n4d013194626ded75b6d4bf708e5b36f1f5159658 172.28.119.236:6379@16379 myself,master - 0 1693819613000 2 connected 5461-10922\n969cd951afe67329683587d34d8387c252e202b1 172.28.122.180:6379@16379 slave 4d013194626ded75b6d4bf708e5b36f1f5159658 0 1693819613764 2 connected\n55b26ca11aa0d1a9accc7fab6a36f8ebd63abaee 172.28.243.249:6379@16379 slave 54c7b5870c207016f20d15da043ca14216ce427b 0 1693819612000 1 connected\n54c7b5870c207016f20d15da043ca14216ce427b 172.28.107.248:6379@16379 master - 0 1693819612000 1 connected 0-5460\n3514d0e38e017c8159ae047efafe5292ad93cb2c 172.28.203.37:6379@16379 slave 30eab827de40b3babcc95f253a4653242df2b676 0 1693819612000 3 connected"
	var clusterNodes []string
	for _, line := range strings.Split(linesText, "\n") {
		splits := strings.Split(line, " ")
		if len(splits) < 2 {
			continue
		}
		println(splits[1])
		clusterNodes = append(clusterNodes, strings.Split(splits[1], "@")[0])
	}
	log.Println(strings.Join(clusterNodes, ","))
}

func TestDecode(t *testing.T) {
	var dst []byte
	println(string(oauth2.OAUTH2))

	pairs := securecookie.CodecsFromPairs([]byte("WWtkT05BPT0"))
	cookieValue := "MTY5MzUzODc1MXxOd3dBTkZkWFZESlBTRUZJVGs5SVZVUTNRa3BFU1ROQ1ZVUlRUVWRSUzFGVFZqVktVVmRIVmt3MU16WTNUa1JMVkU5WVRrSkRTbEU9fGK9JOUKqZfTCqybibIgkaxAGQlvTdvnv0O1aQ784l-M"
	decodeString, _ := base64.RawURLEncoding.DecodeString(cookieValue)
	err := securecookie.DecodeMulti(
		"oauth2_proxy",
		string(decodeString),
		&dst,
		pairs...)
	if err != nil {
		panic(err)
	}
	res := string(dst)
	println(res)

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
