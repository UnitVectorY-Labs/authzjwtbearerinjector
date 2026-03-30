package rsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// generateTestRSAPEM generates a test RSA private key in PEM format
func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	return string(pem.EncodeToMemory(pemBlock))
}

// generateTestRSABase64 generates a test RSA private key as raw base64 (no PEM wrapping)
func generateTestRSABase64(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pkcs8)
}

// generateTestECPEM generates a test EC private key in PEM format
func generateTestECPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	return string(pem.EncodeToMemory(pemBlock))
}

func TestParsePrivateKey_ValidPEM(t *testing.T) {
	pemKey := generateTestRSAPEM(t)
	key, err := ParsePrivateKey(pemKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKey_ValidBase64(t *testing.T) {
	b64Key := generateTestRSABase64(t)
	key, err := ParsePrivateKey(b64Key)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKey_PEMWithEscapedNewlines(t *testing.T) {
	pemKey := generateTestRSAPEM(t)
	// Simulate escaped newlines (e.g. from environment variable)
	escapedKey := string(pemKey)
	// The pemKeyReplacer handles \\n as well as \n
	key, err := ParsePrivateKey(escapedKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestParsePrivateKey_InvalidBase64(t *testing.T) {
	_, err := ParsePrivateKey("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParsePrivateKey_InvalidPKCS8(t *testing.T) {
	// Valid base64 but not a valid PKCS#8 key
	invalidDER := base64.StdEncoding.EncodeToString([]byte("this is not a valid DER key"))
	_, err := ParsePrivateKey(invalidDER)
	if err == nil {
		t.Fatal("expected error for invalid PKCS#8 key")
	}
}

func TestParsePrivateKey_ECKeyReturnsError(t *testing.T) {
	ecPEM := generateTestECPEM(t)
	key, err := ParsePrivateKey(ecPEM)
	if err == nil {
		t.Fatal("expected error for non-RSA key")
	}
	if key != nil {
		t.Fatal("expected nil key for non-RSA key")
	}
	if err.Error() != "not an RSA private key" {
		t.Fatalf("expected 'not an RSA private key' error, got: %v", err)
	}
}

func TestParsePrivateKey_EmptyString(t *testing.T) {
	_, err := ParsePrivateKey("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}
