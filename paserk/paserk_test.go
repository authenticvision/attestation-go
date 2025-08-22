package paserk

import (
	"encoding/hex"
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/assert"
)

func mustDecodeHex(s string) []byte {
	result, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return result
}

func TestEncode(t *testing.T) {
	type args struct {
		key interface{ ExportBytes() []byte }
	}
	tests := []struct {
		name string
		key  string
		want string
	}{
		// via https://github.com/paragonie/paserk-php/blob/master/tests/test-vectors/k4.public.json
		{"k4.public-1", "0000000000000000000000000000000000000000000000000000000000000000", "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"k4.public-2", "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8"},
		{"k4.public-3", "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90", "k4.public.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjpA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := paseto.NewV4AsymmetricPublicKeyFromBytes(mustDecodeHex(tt.key))
			if err != nil {
				panic(err)
			}
			if got := Encode(key); got != tt.want {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyID_Public(t *testing.T) {
	type args struct {
		key interface{ ExportBytes() []byte }
	}
	tests := []struct {
		name string
		key  string
		want string
	}{
		// via https://github.com/paragonie/paserk-php/blob/master/tests/test-vectors/k4.pid.json
		{"k4.pid-1", "0000000000000000000000000000000000000000000000000000000000000000", "k4.pid.S_XQmeEwHbbvRmiyfXfHYpLGjXGzjTRSDoT1YtTakWFE"},
		{"k4.pid-2", "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f", "k4.pid.9ShR3xc8-qVJ_di0tc9nx0IDIqbatdeM2mqLFBJsKRHs"},
		{"k4.pid-3", "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e90", "k4.pid.-nyvbaTz8U6TQz7OZWW-iB3va31iAxIpUgzUcVQVmW9A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := paseto.NewV4AsymmetricPublicKeyFromBytes(mustDecodeHex(tt.key))
			if err != nil {
				panic(err)
			}
			if got := KeyID(key); got != tt.want {
				t.Errorf("KeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyIDFooter(t *testing.T) {
	a := assert.New(t)
	k, err := paseto.V4SymmetricKeyFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	if !a.NoError(err) {
		return
	}
	tests := []struct {
		name string
		key  interface{ ExportBytes() []byte }
		want string
	}{
		{"ok", k, `{"kid":"k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyIDFooter(tt.key); got != tt.want {
				t.Errorf("KeyIDFooter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseKeyIDFooter(t *testing.T) {
	a := assert.New(t)
	k, err := paseto.V4SymmetricKeyFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	if !a.NoError(err) {
		return
	}
	tests := []struct {
		name    string
		footer  string
		key     interface{ ExportBytes() []byte }
		wantErr bool
	}{
		{"ok", `{"kid":"k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"}`, k, false},
		{"not json", `hi`, nil, true},
		{"not paserk", `{"kid":"x4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559"}`, nil, true},
		{"no claim", `{"hi":"ho"}`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyIDFooter(tt.footer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKeyIDFooter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got != KeyID(tt.key) {
				t.Errorf("ParseKeyIDFooter() got = %v, want %v", got, KeyID(tt.key))
			}
		})
	}
}
