package xyz

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"time"
)

type StateRedis struct {
	RedisCli     redis.UniversalClient
	UriParamName string
	Expire       time.Duration
}

func CreateStateRedis(
	cli redis.UniversalClient,
	expire time.Duration,
	rup string) *StateRedis {
	return &StateRedis{
		RedisCli:     cli,
		UriParamName: rup,
		Expire:       expire,
	}
}

func (svc *StateRedis) Key(state string) string {
	return "oauth2_proxy:state:" + state
}

func (svc *StateRedis) Create(c *gin.Context) (s string, err error) {
	ru := c.Query(svc.UriParamName)
	if ru == "" {
		return "", errors.New("not found redirect uri in query param:" + svc.UriParamName)
	}
	b := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	ex := svc.RedisCli.SetEx(context.Background(), svc.Key(state), ru, svc.Expiration())
	return state, ex.Err()
}

func (svc *StateRedis) Get(c *gin.Context) (*StateInf, error) {
	state := c.Query("state")
	log.Println("StateRedis query state[" + state + "]")
	ru, err := svc.RedisCli.Get(context.Background(), svc.Key(state)).Result()
	if err != nil {
		return nil, err
	}
	return &StateInf{Value: state, RedirectUri: ru}, nil
}

func (svc *StateRedis) Expiration() time.Duration {
	return svc.Expire
}

func (svc *StateRedis) RedirectUriParamName() string {
	return svc.UriParamName
}
