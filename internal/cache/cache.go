package cache

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	config "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/config"
	jwt "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/jwt"
	logger "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/logger"
	oauth "github.com/UnitVectorY-Labs/authzjwtbearerinjector/internal/oauth"
)

var (
	tokenCache       = sync.Map{}
	createTokenMutex = sync.Mutex{}
)

type CachedToken struct {
	TokenValue CachedTokenValue
	Mutex      sync.Mutex
}

type CachedTokenValue struct {
	Token      string
	Expiry     time.Time
	SoftExpiry time.Time
	Issued     time.Time
}

func GetCachedToken(config config.Config, privateKey *rsa.PrivateKey, metadataTokenHeader map[string]string, metadataTokenPayload map[string]string, metadataOauthRequest map[string]string) (string, error) {
	// Step 1: Hash the metadata Claims to create a unique cache key
	cacheKey := hashClaims(metadataTokenHeader, metadataTokenPayload, metadataOauthRequest)

	logger.DebugLog("getCachedToken: %s", cacheKey)

	// Step 2: Try to load the cached token entry
	cachedEntry, exists := tokenCache.Load(cacheKey)

	var cachedToken *CachedToken

	if !exists {
		// Step 3: Lock to ensure that only one goroutine can create a new token for the same cache key
		createTokenMutex.Lock()
		defer createTokenMutex.Unlock()

		// Check again if the token was created while waiting for the lock
		cachedEntry, exists = tokenCache.Load(cacheKey)

		if !exists {
			// Step 4: If no cached entry exists, create a new one with a locked mutex to block other requests
			newCachedToken := &CachedToken{
				Mutex: sync.Mutex{},
			}
			tokenCache.Store(cacheKey, newCachedToken)
			cachedToken = newCachedToken

			logger.DebugLog("Cache miss with token for: %s", cacheKey)
		}
	}

	if exists {
		// Step 5: Type assert the cached entry as *CachedToken
		cachedToken = cachedEntry.(*CachedToken)

		if logger.IsDebugLogEnabled() {
			// Token found, log how long until the token expires
			timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
			logger.DebugLog("Token found in cache, expires in: %s", timeTillExpiry)
			// And the soft expiration time
			timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
			logger.DebugLog("Token found in cache, soft expires in: %s", timeTillSoftExpiry)
		}

		// Step 6: Check if the token is still within soft expiry
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			logger.DebugLog("Returning cached token for: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}
	}

	logger.DebugLog("Waiting for lock on: %s", cacheKey)

	// Step 7: Lock the token generation if it hasn't been done yet
	cachedToken.Mutex.Lock()
	defer cachedToken.Mutex.Unlock()

	logger.DebugLog("Lock acquired on: %s", cacheKey)

	// Step 8: After locking, check again if the token is still valid
	if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
		logger.DebugLog("Returning cached generated after getting lock token for: %s", cacheKey)
		return cachedToken.TokenValue.Token, nil
	}

	// Step 9: Generate a new JWT
	localJWT, err := jwt.SignLocalJWT(config, privateKey, metadataTokenHeader, metadataTokenPayload)
	if err != nil {
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			logger.DebugLog("Soft expired token generation failed, using existing token: %s. Error: %v", cacheKey, err)
			return cachedToken.TokenValue.Token, nil
		}
		logger.DebugLog("Failed to generate new token: %s. Error: %v", cacheKey, err)
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}

	// Step 10: Exchange the local JWT for an actual token
	token, expiry, issuedAt, err := oauth.ExchangeJWTBearerForToken(config, localJWT, metadataOauthRequest)
	if err != nil {
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			logger.DebugLog("Soft expired token exchange failed, using existing token: %s. Error: %v", cacheKey, err)
			return cachedToken.TokenValue.Token, nil
		}
		logger.DebugLog("Failed to exchange token: %s. Error: %v", cacheKey, err)
		return "", fmt.Errorf("failed to exchange token: %w", err)
	}

	// Step 11: Calculate soft expiry based on the configurable lifetime ratio
	lifetime := expiry.Sub(issuedAt)
	softExpiry := time.Now().Add(time.Duration(float32(lifetime) * float32(config.SoftTokenLifetime)))

	// Step 12: Update the cached token value
	newCachedTokenValue := CachedTokenValue{
		Token:      token,
		Expiry:     expiry,
		SoftExpiry: softExpiry,
		Issued:     issuedAt,
	}

	cachedToken.TokenValue = newCachedTokenValue

	if logger.IsDebugLogEnabled() {
		// Log how long until the token expires
		timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
		logger.DebugLog("New token generated, expires in: %s", timeTillExpiry)
		// And the soft expiration time
		timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
		logger.DebugLog("New token generated, soft expires in: %s", timeTillSoftExpiry)

		logger.DebugLog("New token request successful: %s", cacheKey)
	}

	return token, nil
}

func hashClaims(metadataTokenHeader map[string]string, metadataTokenPayload map[string]string, metadataOauthRequest map[string]string) string {
	h := sha256.New()

	// Combine all maps into a single map with prefixes to separate them
	combinedClaims := make(map[string]string)
	for k, v := range metadataTokenHeader {
		combinedClaims["header_"+k] = v
	}
	for k, v := range metadataTokenPayload {
		combinedClaims["payload_"+k] = v
	}
	for k, v := range metadataOauthRequest {
		combinedClaims["oauth_"+k] = v
	}

	// Extract the keys from the combined map and sort them
	keys := make([]string, 0, len(combinedClaims))
	for k := range combinedClaims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write the sorted key-value pairs to the hash
	for _, k := range keys {
		h.Write([]byte(fmt.Sprintf("%s:%v", k, combinedClaims[k])))
	}

	// Return the final hash as a hexadecimal string
	return hex.EncodeToString(h.Sum(nil))
}
