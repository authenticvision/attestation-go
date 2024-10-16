package attestation

import (
	"aidanwoods.dev/go-paseto"
	"errors"
	"fmt"
	"github.com/authenticvision/attestation-go/paserk"
	"io"
	"net/http"
	"sync"
)

var ErrNoSuchKey = errors.New("no such SIPv4 key")

var SharedKeyStore = &KeyStore{
	Client: http.DefaultClient,
	Hosts:  []string{"sip-keys.authenticvision.com"},
	keys:   make(map[string]paseto.V4AsymmetricPublicKey),
}

type KeyStore struct {
	Client *http.Client
	Hosts  []string
	keys   map[string]paseto.V4AsymmetricPublicKey
	mutex  sync.RWMutex
}

func (ks *KeyStore) AddPublicKey(key paseto.V4AsymmetricPublicKey) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()
	ks.keys[paserk.KeyID(key)] = key
}

func (ks *KeyStore) getPublicKeyIfExists(id string) (key paseto.V4AsymmetricPublicKey, ok bool) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()
	key, ok = ks.keys[id]
	return
}

func (ks *KeyStore) GetPublicKey(id string) (key paseto.V4AsymmetricPublicKey, err error) {
	var keyPresent bool
	key, keyPresent = ks.getPublicKeyIfExists(id)
	if keyPresent {
		return
	}
	for _, host := range ks.Hosts {
		if key, err = ks.getPublicKeyForHost(id, host); err == nil {
			ks.AddPublicKey(key)
			return
		}
	}
	return
}

func (ks *KeyStore) getPublicKeyForHost(id, host string) (key paseto.V4AsymmetricPublicKey, err error) {
	if resp, err := ks.Client.Get("https://" + host + "/v4/" + id); err != nil {
		return key, fmt.Errorf("failed to get key: %w", err)
	} else {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return key, ErrNoSuchKey
		}
		if resp.StatusCode != http.StatusOK {
			return key, fmt.Errorf("non-ok HTTP response code %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return key, fmt.Errorf("failed to read key request body: %w", err)
		}

		if key, err := paserk.ParsePublic(string(body)); err != nil {
			return key, fmt.Errorf("failed to parse public key: %w", err)
		} else {
			return key, nil
		}
	}
}
