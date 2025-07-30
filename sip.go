package attestation

import (
	"aidanwoods.dev/go-paseto"
	"context"
	"encoding/json"
	"errors"
	"github.com/authenticvision/attestation-go/paserk"
	"github.com/authenticvision/util-go/logutil"
	"log/slog"
	"net/http"
)

const Version = 4

type Result string

const (
	ResultAuthentic    Result = "AUTHENTIC"
	ResultCounterfeit  Result = "COUNTERFEIT"
	ResultInconclusive Result = "INCONCLUSIVE"
)

type Reason string

const (
	ReasonNone        Reason = ""
	ReasonBlacklisted Reason = "BLACKLISTED"
	ReasonInactive    Reason = "INACTIVE"
	ReasonSignature   Reason = "SIGNATURE"
	ReasonVoid        Reason = "VOID"
	ReasonDisplay     Reason = "DISPLAY"
)

type Location struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
}

type Token struct {
	Version    int               `json:"_v"`
	Audience   string            `json:"aud"`
	Expiration RFC3339Time       `json:"exp"`
	IssuedAt   RFC3339Time       `json:"iat"`
	SessionID  string            `json:"jti"`
	SLID       SLID36            `json:"slid"`
	GTIN       string            `json:"gtin,omitempty"`
	Result     Result            `json:"result"`
	Reason     Reason            `json:"reason"`
	Location   *Location         `json:"location,omitempty"`
	ExtRefs    []json.RawMessage `json:"extrefs,omitempty"`
}

type Middleware struct {
	KeyStore *KeyStore
	Required bool
}

func NewMiddleware() *Middleware {
	return &Middleware{KeyStore: SharedKeyStore, Required: true}
}

func (s *Middleware) Middleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("av_sip4")
		if token == "" {
			if s.Required {
				http.Error(w, "This server serves responses for Authentic Vision Mobile SDK "+
					"applications and cannot be used directly. The av_sip4 query parameter is required.",
					http.StatusBadRequest)
				return
			} else {
				handler.ServeHTTP(w, r)
				return
			}
		}

		log := logutil.FromContext(r.Context())
		log = log.With(slog.String("sip4_token", token))

		// SIP token validation
		// expiration checks are handled by the default rule added in NewParser
		var err error
		var claims Token
		p := paseto.NewParser()
		footer, err := p.UnsafeParseFooter(paseto.V4Public, token)
		if err != nil {
			log.Warn("SIP token parsing failed", logutil.Err(err))
			http.Error(w, "SIP token parsing failed", http.StatusBadRequest)
			return
		}
		kid, err := paserk.ParseKeyIDFooter(string(footer))
		if err != nil {
			log.Warn("SIP token footer parsing failed", logutil.Err(err))
			http.Error(w, "SIP token footer parsing failed", http.StatusBadRequest)
			return
		}
		publicKey, err := s.KeyStore.GetPublicKey(kid)
		if errors.Is(err, ErrNoSuchKey) {
			log.Warn("no such SIPv4 key", logutil.Err(err))
			http.Error(w, "SIP key not trusted", http.StatusForbidden)
			return
		} else if err != nil {
			log.Warn("could not retrieve SIPv4 key", logutil.Err(err))
			http.Error(w, "SIP key unavailable", http.StatusServiceUnavailable)
			return
		}
		t, err := p.ParseV4Public(publicKey, token, nil)
		if err != nil {
			log.Warn("SIP token decryption failed", logutil.Err(err))
			http.Error(w, "SIP token invalid", http.StatusForbidden)
			return
		}
		if err := json.Unmarshal(t.ClaimsJSON(), &claims); err != nil {
			log.Warn("claims unmarshalling failed", logutil.Err(err))
			http.Error(w, "SIP token invalid", http.StatusInternalServerError)
			return
		}
		if claims.Version != Version {
			log.Warn("SIP token has wrong version", slog.Int("expected", 4),
				slog.Int("got", claims.Version), logutil.Err(err))
			http.Error(w, "SIP token has wrong version", http.StatusBadRequest)
			return
		}

		log = log.With(slog.String("slid", string(claims.SLID)))
		ctx := r.Context()
		ctx = logutil.WithLogContext(r.Context(), log)
		ctx = context.WithValue(ctx, tokenTag{}, &claims)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

type tokenTag struct{}

func FromContext(ctx context.Context) *Token {
	if v, ok := ctx.Value(tokenTag{}).(*Token); ok {
		return v
	} else {
		return nil
	}
}
