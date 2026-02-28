package cache

import (
	"testing"
)

func TestHashClaims_ConsistentHashing(t *testing.T) {
	header := map[string]string{"kid": "key1"}
	payload := map[string]string{"iss": "issuer", "sub": "subject"}
	oauth := map[string]string{"grant_type": "jwt-bearer"}

	hash1 := hashClaims(header, payload, oauth)
	hash2 := hashClaims(header, payload, oauth)

	if hash1 != hash2 {
		t.Errorf("expected same hash for same input, got: %s and %s", hash1, hash2)
	}
}

func TestHashClaims_DifferentInputsDifferentHashes(t *testing.T) {
	header1 := map[string]string{"kid": "key1"}
	header2 := map[string]string{"kid": "key2"}
	payload := map[string]string{"iss": "issuer"}
	oauth := map[string]string{}

	hash1 := hashClaims(header1, payload, oauth)
	hash2 := hashClaims(header2, payload, oauth)

	if hash1 == hash2 {
		t.Error("expected different hashes for different inputs")
	}
}

func TestHashClaims_EmptyMaps(t *testing.T) {
	hash := hashClaims(map[string]string{}, map[string]string{}, map[string]string{})
	if hash == "" {
		t.Error("expected non-empty hash for empty maps")
	}
}

func TestHashClaims_NilMaps(t *testing.T) {
	hash := hashClaims(nil, nil, nil)
	if hash == "" {
		t.Error("expected non-empty hash for nil maps")
	}
}

func TestHashClaims_OrderIndependent(t *testing.T) {
	// Maps are inherently unordered, but the hash function sorts keys
	// so the hash should be the same regardless of insertion order
	payload1 := map[string]string{"a": "1", "b": "2", "c": "3"}
	payload2 := map[string]string{"c": "3", "a": "1", "b": "2"}

	hash1 := hashClaims(nil, payload1, nil)
	hash2 := hashClaims(nil, payload2, nil)

	if hash1 != hash2 {
		t.Errorf("expected same hash regardless of map order, got: %s and %s", hash1, hash2)
	}
}

func TestHashClaims_PrefixIsolation(t *testing.T) {
	// A key in header vs payload should produce different hashes
	// because the prefix "header_" vs "payload_" differentiates them
	header := map[string]string{"key": "value"}
	payload := map[string]string{"key": "value"}

	hashHeaderOnly := hashClaims(header, nil, nil)
	hashPayloadOnly := hashClaims(nil, payload, nil)

	if hashHeaderOnly == hashPayloadOnly {
		t.Error("expected different hashes for header vs payload with same key-value")
	}
}

func TestHashClaims_HexOutput(t *testing.T) {
	hash := hashClaims(map[string]string{"k": "v"}, nil, nil)
	// SHA-256 produces 64 hex characters
	if len(hash) != 64 {
		t.Errorf("expected 64 character hex hash, got %d characters: %s", len(hash), hash)
	}
}
