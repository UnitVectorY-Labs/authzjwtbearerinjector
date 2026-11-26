package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/config"
)

func TestSignLocalJWTJSON(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignLocalJWT(config.Config{TokenPayload: map[string]string{"sub": "example"}}, key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token: %q", token)
	}
	for i, want := range []map[string]any{{"alg": "RS256", "typ": "JWT"}, {"sub": "example"}} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %v, want %v", k, got[k], v)
			}
		}
	}
	for _, cfg := range []config.Config{{TokenHeader: map[string]string{"bad": "\xff"}}, {TokenPayload: map[string]string{"bad": "\xff"}}} {
		if _, err := SignLocalJWT(cfg, key, nil, nil); err == nil {
			t.Error("expected invalid UTF-8 to fail")
		}
	}
}
