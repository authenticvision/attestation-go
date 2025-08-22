package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"aidanwoods.dev/go-paseto"
	"github.com/authenticvision/attestation-go/paserk"
	"github.com/authenticvision/util-go/httpp"
	"github.com/authenticvision/util-go/logutil"
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
	Param    string
}

func NewMiddleware() *Middleware {
	return &Middleware{
		KeyStore: SharedKeyStore,
		Required: true,
		Param:    "av_sip4",
	}
}

func (m *Middleware) Middleware(next httpp.Handler) httpp.Handler {
	return &handler{m: m, next: next}
}

type handler struct {
	m    *Middleware
	next httpp.Handler
}

func (h *handler) ServeErrHTTP(w http.ResponseWriter, r *http.Request) error {
	token := r.URL.Query().Get("av_sip4")
	if token == "" {
		if h.m.Required {
			return httpp.Unauthorized("This server serves responses for Authentic Vision Mobile SDK " +
				"applications and cannot be used directly. The av_sip4 query parameter is required.")
		} else {
			return h.next.ServeErrHTTP(w, r)
		}
	}

	// SIP token validation
	// expiration checks are handled by the default rule added in NewParser
	var err error
	var claims Token
	p := paseto.NewParser()
	footer, err := p.UnsafeParseFooter(paseto.V4Public, token)
	if err != nil {
		return httpp.BadRequest(err, "invalid SIP token format")
	}
	kid, err := paserk.ParseKeyIDFooter(string(footer))
	if err != nil {
		return httpp.BadRequest(err, "invalid SIP token footer")
	}
	publicKey, err := h.m.KeyStore.GetPublicKey(kid)
	if errors.Is(err, ErrNoSuchKey) {
		return httpp.Forbidden("SIP key is not trusted")
	} else if err != nil {
		return httpp.Err(nil, http.StatusServiceUnavailable, "SIP key service unavailable")
	}
	t, err := p.ParseV4Public(publicKey, token, nil)
	if err != nil {
		return httpp.Err(err, http.StatusForbidden, "SIP token rejected")
	}
	if err := json.Unmarshal(t.ClaimsJSON(), &claims); err != nil {
		return httpp.BadRequest(err, "invalid SIP token claims")
	}
	if claims.Version != Version {
		return httpp.BadRequest(nil, "unsupported SIP token version")
	}

	ctx := r.Context()
	log := logutil.FromContext(ctx).With(slog.String("slid", string(claims.SLID)))
	ctx = logutil.WithLogContext(r.Context(), log)
	ctx = context.WithValue(ctx, tokenTag{}, &claims)
	return h.next.ServeErrHTTP(w, r.WithContext(ctx))
}

type tokenTag struct{}

func FromContext(ctx context.Context) *Token {
	if v, ok := ctx.Value(tokenTag{}).(*Token); ok {
		return v
	} else {
		return nil
	}
}
