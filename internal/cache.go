package internal

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
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

func GetCachedToken(config Config, privateKey *rsa.PrivateKey, metadataClaims map[string]string) (string, error) {
	// Step 1: Hash the metadataClaims to create a unique cache key
	cacheKey := hashClaims(metadataClaims)

	DebugLog("getCachedToken: %s", cacheKey)

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

			DebugLog("Cache miss with token for: %s", cacheKey)
		}
	}

	if exists {
		// Step 5: Type assert the cached entry as *CachedToken
		cachedToken = cachedEntry.(*CachedToken)

		if IsDebugLogEnabled() {
			// Token found, log how long until the token expires
			timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
			DebugLog("Token found in cache, expires in: %s", timeTillExpiry)
			// And the soft expiration time
			timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
			DebugLog("Token found in cache, soft expires in: %s", timeTillSoftExpiry)
		}

		// Step 6: Check if the token is still within soft expiry
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			DebugLog("Returning cached token for: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}
	}

	DebugLog("Waiting for lock on: %s", cacheKey)

	// Step 7: Lock the token generation if it hasn't been done yet
	cachedToken.Mutex.Lock()
	defer cachedToken.Mutex.Unlock()

	DebugLog("Lock acquired on: %s", cacheKey)

	// Step 8: After locking, check again if the token is still valid
	if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
		DebugLog("Returning cached generated after getting lock token for: %s", cacheKey)
		return cachedToken.TokenValue.Token, nil
	}

	// Step 9: Generate a new JWT
	localJWT, err := SignLocalJWT(config, privateKey, metadataClaims)
	if err != nil {
		// If generation fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			DebugLog("Soft expired token generate failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		DebugLog("Expired token generated failed: %s", cacheKey)
		return "", err
	}

	// Step 10: Exchange the local JWT for an actual token
	token, expiry, issuedAt, err := ExchangeJWTBearerForToken(config, localJWT)
	if err != nil {
		// If token exchange fails, return the cached token if it's still valid
		if time.Now().Before(cachedToken.TokenValue.SoftExpiry) {
			DebugLog("Soft expired token exchange failed, using existing token: %s", cacheKey)
			return cachedToken.TokenValue.Token, nil
		}

		DebugLog("Expired token exchange failed: %s", cacheKey)
		// If the cached token is also expired, return an error
		return "", err
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

	if IsDebugLogEnabled() {
		// Log how long until the token expires
		timeTillExpiry := cachedToken.TokenValue.Expiry.Sub(time.Now())
		DebugLog("New token generated, expires in: %s", timeTillExpiry)
		// And the soft expiration time
		timeTillSoftExpiry := cachedToken.TokenValue.SoftExpiry.Sub(time.Now())
		DebugLog("New token generated, soft expires in: %s", timeTillSoftExpiry)

		DebugLog("New token request successful: %s", cacheKey)
	}

	return token, nil
}

func hashClaims(claims map[string]string) string {
	h := sha256.New()
	// Extract the keys from the map and sort them
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write the sorted key-value pairs to the hash
	for _, k := range keys {
		h.Write([]byte(fmt.Sprintf("%s:%v", k, claims[k])))
	}

	// Return the final hash as a hexadecimal string
	return hex.EncodeToString(h.Sum(nil))
}