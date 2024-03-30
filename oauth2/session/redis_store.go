package session

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	sessions2 "github.com/gin-contrib/sessions"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	redisV9 "github.com/redis/go-redis/v9"
	"log"
	"net/http"
	"strings"
	"time"
)

// Amount of time for cookies/redis keys to expire.
var sessionExpire = 86400 * 30

// Serializer provides an interface hook for alternative serializers
type Serializer interface {
	Deserialize(d []byte, ss *sessions.Session) error
	Serialize(ss *sessions.Session) ([]byte, error)
}

// JSONSerializer encode the session map to JSON.
type JSONSerializer struct{}

// Serialize to JSON. Will err if there are unmarshalable key values
func (s JSONSerializer) Serialize(ss *sessions.Session) ([]byte, error) {
	m := make(map[string]interface{}, len(ss.Values))
	for k, v := range ss.Values {
		ks, ok := k.(string)
		if !ok {
			err := fmt.Errorf("non-string key value, cannot serialize session to JSON: %v", k)
			fmt.Printf("redistore.JSONSerializer.serialize() Error: %v", err)
			return nil, err
		}
		m[ks] = v
	}
	return json.Marshal(m)
}

// Deserialize back to map[string]interface{}
func (s JSONSerializer) Deserialize(d []byte, ss *sessions.Session) error {
	m := make(map[string]interface{})
	err := json.Unmarshal(d, &m)
	if err != nil {
		fmt.Printf("redistore.JSONSerializer.deserialize() Error: %v", err)
		return err
	}
	for k, v := range m {
		ss.Values[k] = v
	}
	return nil
}

// GobSerializer uses gob package to encode the session map
type GobSerializer struct{}

// Serialize using gob
func (s GobSerializer) Serialize(ss *sessions.Session) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(ss.Values)
	if err == nil {
		return buf.Bytes(), nil
	}
	return nil, err
}

// Deserialize back to map[interface{}]interface{}
func (s GobSerializer) Deserialize(d []byte, ss *sessions.Session) error {
	dec := gob.NewDecoder(bytes.NewBuffer(d))
	return dec.Decode(&ss.Values)
}

// RedisStore stores sessions in a redis backend.
type RedisStore struct {
	RedisCli      redisV9.UniversalClient
	Codecs        []securecookie.Codec
	Opts          *sessions.Options // default configuration
	DefaultMaxAge int               // default Redis TTL for a MaxAge == 0 session
	maxLength     int
	keyPrefix     string
	serializer    Serializer
}

func (s *RedisStore) Options(options sessions2.Options) {
	s.Opts = options.ToGorillaOptions()
}

// SetMaxLength sets RedisStore.maxLength if the `l` argument is greater or equal 0
// maxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new RediStore is 4096. Redis allows for max.
// value sizes of up to 512MB (http://redis.io/topics/data-types)
// Default: 4096,
func (s *RedisStore) SetMaxLength(l int) {
	if l >= 0 {
		s.maxLength = l
	}
}

// SetKeyPrefix set the prefix
func (s *RedisStore) SetKeyPrefix(p string) {
	s.keyPrefix = p
}

// SetSerializer sets the serializer
func (s *RedisStore) SetSerializer(ss Serializer) {
	s.serializer = ss
}

// SetMaxAge restricts the maximum age, in seconds, of the session record
// both in database and a browser. This is to change session storage configuration.
// If you want just to remove session use your session `s` object and change it's
// `Options.MaxAge` to -1, as specified in
//
//	http://godoc.org/github.com/gorilla/sessions#Options
//
// Default is the one provided by this package value - `sessionExpire`.
// Set it to 0 for no restriction.
// Because we use `MaxAge` also in SecureCookie crypting algorithm you should
// use this function to change `MaxAge` value.
func (s *RedisStore) SetMaxAge(v int) {
	var c *securecookie.SecureCookie
	var ok bool
	s.Opts.MaxAge = v
	for i := range s.Codecs {
		if c, ok = s.Codecs[i].(*securecookie.SecureCookie); ok {
			c.MaxAge(v)
		} else {
			fmt.Printf("Can't change MaxAge on codec %v\n", s.Codecs[i])
		}
	}
}

// NewRedisStore returns a new RediStore.
// cli: is an abstract c
// NewRedisStore instantiates a RediStore with a cli passed in.
func NewRedisStore(cli redisV9.UniversalClient, keyPrefix string, keyPairs ...[]byte) (*RedisStore, error) {
	rs := &RedisStore{
		RedisCli: cli,
		Codecs:   securecookie.CodecsFromPairs(keyPairs...),
		Opts: &sessions.Options{
			Path:   "/",
			MaxAge: sessionExpire,
		},
		DefaultMaxAge: 60 * 20, // 20 minutes seems like a reasonable default
		maxLength:     4096,
		keyPrefix:     keyPrefix,
		serializer:    JSONSerializer{},
	}
	_, err := rs.ping()
	return rs, err
}

// Close closes the underlying *redis.Pool
func (s *RedisStore) Close() error {
	return s.RedisCli.Close()
}

// Get returns a session for the given name after adding it to the registry.
//
// See gorilla/sessions FilesystemStore.GetState().
func (s *RedisStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See gorilla/sessions FilesystemStore.New().
func (s *RedisStore) New(r *http.Request, name string) (*sessions.Session, error) {
	var (
		err error
		ok  bool
	)
	session := sessions.NewSession(s, name)
	// make a copy
	options := *s.Opts
	session.Options = &options
	session.IsNew = true
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			ok, err = s.load(session)
			session.IsNew = !(err == nil && ok) // not new if no error and data available
		}
		if err != nil {
			log.Println("error decode cookie,", err.Error())
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *RedisStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge <= 0 {
		if err := s.delete(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
	} else {
		// Build an alphanumeric key for the redis store.
		if session.ID == "" {
			session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
		}
		if err := s.save(session); err != nil {
			return err
		}
		encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

// Delete removes the session from redis, and sets the cookie to expire.
//
// WARNING: This method should be considered deprecated since it is not exposed via the gorilla/sessions interface.
// Set session.Options.MaxAge = -1 and call Save instead. - July 18th, 2013
func (s *RedisStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	del := s.RedisCli.Del(context.Background(), s.keyPrefix+session.ID)
	err := del.Err()
	if err != nil {
		return err
	}
	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}
	return nil
}

// ping does an internal ping against a server to check if it is alive.
func (s *RedisStore) ping() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ping := s.RedisCli.Ping(ctx)
	err := ping.Err()

	if err != nil {
		return false, err
	}
	result, err := ping.Result()
	if err != nil {
		return false, err
	}
	return result == "PONG", nil
}

// save stores the session in redis.
func (s *RedisStore) save(session *sessions.Session) error {
	b, err := s.serializer.Serialize(session)
	if err != nil {
		return err
	}
	if s.maxLength != 0 && len(b) > s.maxLength {
		return errors.New("SessionStore: the value to store is too big")
	}
	age := session.Options.MaxAge
	if age == 0 {
		age = s.DefaultMaxAge
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.RedisCli.SetEx(ctx, s.keyPrefix+session.ID, b, time.Duration(age)*time.Second).Err()
}

// load reads the session from redis.
// returns true if there is a sessoin data in DB
func (s *RedisStore) load(session *sessions.Session) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := s.RedisCli.Get(ctx, s.keyPrefix+session.ID)
	err := res.Err()
	if err != nil {
		return false, err
	}
	result, err := res.Result()
	if err != nil {
		return false, err
	}
	return true, s.serializer.Deserialize([]byte(result), session)
}

// delete removes keys from redis if MaxAge<0
func (s *RedisStore) delete(session *sessions.Session) error {
	res := s.RedisCli.Del(context.Background(), s.keyPrefix+session.ID)
	err := res.Err()
	if err != nil {
		return err
	}
	return nil
}
