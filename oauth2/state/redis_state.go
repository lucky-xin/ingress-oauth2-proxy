package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/lucky-xin/ingress-oauth2-proxy/oauth2"
	"github.com/lucky-xin/xyz-common-go/pointer"
	"github.com/lucky-xin/xyz-common-go/text"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"time"
)

var (
	MagicByte = byte(9)
)

type State struct {
	rcli         redis.UniversalClient
	uriParamName string
	secret       string
	expire       time.Duration
}

func Create(
	cli redis.UniversalClient,
	expire time.Duration,
	rup, secret string) *State {
	return &State{
		rcli:         cli,
		uriParamName: rup,
		secret:       secret,
		expire:       expire,
	}
}

func (svc *State) Key(state string) string {
	return "oauth2_proxy:state:" + state
}

func (svc *State) Create(c *gin.Context) (s string, err error) {
	ru := c.Query(svc.uriParamName)
	if ru == "" {
		return "", errors.New("not found redirect uri in query param:" + svc.uriParamName)
	}
	b1, err := createRandomBytes(24)
	if err != nil {
		return
	}
	b2, err := createRandomBytes(4)
	if err != nil {
		return
	}
	block := text.Block{
		MagicByte: pointer.Ptr(MagicByte),
		Segments: []*text.Segment{
			{Length: len(b1), Bytes: b1},
			{Length: len(b2), Bytes: b2},
		}}
	buff, err := block.ToBuffer()
	if err != nil {
		return
	}
	state := base64.StdEncoding.EncodeToString(buff.Bytes())
	ex := svc.rcli.SetEx(context.Background(), svc.Key(state), ru, svc.Expiration())
	return state, ex.Err()
}

func (svc *State) Get(c *gin.Context) (*oauth2.StateInf, error) {
	state := c.Query("state")
	log.Println("query redis state[" + state + "]")
	ru, err := svc.rcli.Get(context.Background(), svc.Key(state)).Result()
	if err != nil {
		return nil, err
	}
	return &oauth2.StateInf{Value: state, RedirectUri: ru}, nil
}

func (svc *State) Expiration() time.Duration {
	return svc.expire
}

func (svc *State) RedirectUriParamName() string {
	return svc.uriParamName
}

func createRandomBytes(len int) (byts []byte, err error) {
	b := make([]byte, len)
	if _, err = io.ReadFull(rand.Reader, b); err != nil {
		return
	}
	byts = b
	return
}
