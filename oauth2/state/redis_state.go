package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"time"
)

type State struct {
	RedisCli     redis.UniversalClient
	UriParamName string
	Expire       time.Duration
}

func Create(
	cli redis.UniversalClient,
	expire time.Duration,
	rup string) *State {
	return &State{
		RedisCli:     cli,
		UriParamName: rup,
		Expire:       expire,
	}
}

func (svc *State) Key(state string) string {
	return "oauth2_proxy:state:" + state
}

func (svc *State) Create(c *gin.Context) (s string, err error) {
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

func (svc *State) Get(c *gin.Context) (*oauth2.StateInf, error) {
	state := c.Query("state")
	log.Println("StateRedis query state[" + state + "]")
	ru, err := svc.RedisCli.Get(context.Background(), svc.Key(state)).Result()
	if err != nil {
		return nil, err
	}
	return &oauth2.StateInf{Value: state, RedirectUri: ru}, nil
}

func (svc *State) Expiration() time.Duration {
	return svc.Expire
}

func (svc *State) RedirectUriParamName() string {
	return svc.UriParamName
}
