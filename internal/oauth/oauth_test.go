package oauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/config"
)

func TestExchangeJSONResponse(t *testing.T) {
	tests := []struct {
		name, body string
		wantErr    bool
	}{
		{"valid", `{"access_token":"token"}`, false},
		{"duplicate key", `{"access_token":"one","access_token":"two"}`, true},
		{"invalid UTF-8", "{\"access_token\":\"\xff\"}", true},
		{"trailing value", `{"access_token":"token"} {}`, true},
		{"case sensitive field", `{"Access_Token":"token"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tt.body)) }))
			defer server.Close()
			token, _, _, err := ExchangeJWTBearerForToken(config.Config{OauthTokenUrl: server.URL, OauthResponseField: "access_token"}, "jwt", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if !tt.wantErr && token != "token" {
				t.Fatalf("token = %q", token)
			}
		})
	}
}

func TestExpirationClaimsJSON(t *testing.T) {
	for _, tt := range []struct {
		name, payload string
		valid         bool
	}{
		{"valid", `{"exp":2000000000,"iat":1900000000}`, true},
		{"duplicate", `{"exp":2000000000,"exp":2100000000,"iat":1900000000}`, false},
		{"invalid UTF-8", "{\"exp\":2000000000,\"x\":\"\xff\"}", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(tt.payload)) + ".signature"
			exp, iat := extractExpirationClaims(token)
			if tt.valid {
				if exp.Unix() != 2000000000 || iat.Unix() != 1900000000 {
					t.Fatalf("claims = %v, %v", exp, iat)
				}
			} else if exp.Before(before.Add(time.Hour)) || iat.Before(before) || exp.After(time.Now().Add(time.Hour)) || iat.After(time.Now()) {
				t.Fatalf("expected defaults, got %v, %v", exp, iat)
			}
		})
	}
}
