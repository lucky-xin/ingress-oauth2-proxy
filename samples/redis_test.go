package samples

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/gorilla/securecookie"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-common-go/text"
	"github.com/redis/go-redis/v9"
	"testing"
	"time"
)

func TestSaveSecret(t *testing.T) {
	byts := [][]byte{
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	}
	initKey := oauth2.SessionName + ":cookie_secret"
	rcli := redis.NewClient(
		&redis.Options{
			Addr:     env.GetString("REDIS_NODES", "127.0.0.1:6379"),
			Password: env.GetString("REDIS_PWD", ""),
			DB:       9,
		})
	var segments []*text.Segment
	for i := range byts {
		b := byts[i]
		segments = append(segments, &text.Segment{Length: len(b), Bytes: b})
	}
	block := text.Block{Segments: segments}
	buff, err := block.ToBuffer()
	if err != nil {
		return
	}
	secret := base64.StdEncoding.EncodeToString(buff.Bytes())
	_, err = rcli.Set(context.Background(), initKey, secret, time.Hour*87600).Result()
	if err != nil {
		panic(err)
	}
	res, err := rcli.Get(context.Background(), initKey).Result()
	s, err := base64.StdEncoding.DecodeString(res)
	if err != nil {
		panic(err)
	}
	var buffer bytes.Buffer
	_, err = buffer.Write(s)
	if err != nil {
		panic(err)
	}
	fromBuffer, err := text.FromBuffer(nil, &buffer)
	if err != nil {
		panic(err)
	}
	println(len(fromBuffer.Segments))
}
