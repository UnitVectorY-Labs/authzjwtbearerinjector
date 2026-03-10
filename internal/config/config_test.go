package config

import (
	"os"
	"path/filepath"
	"testing"
)

// clearConfigEnvVars removes all environment variables that affect config
func clearConfigEnvVars(t *testing.T) {
	t.Helper()
	envVars := []string{
		envConfigFilePath,
		envPrivateKey,
		envOauth2TokenURL,
		envOauth2ResponseField,
		envSoftTokenLifetime,
		"DEBUG",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}
	// Also clear any TOKEN_HEADER_, TOKEN_PAYLOAD_, OAUTH_REQUEST_ vars
	for _, e := range os.Environ() {
		key := e[:len(e)-len(e)+len(e)]
		for i, ch := range e {
			if ch == '=' {
				key = e[:i]
				break
			}
		}
		if len(key) > 13 && key[:13] == "TOKEN_HEADER_" {
			os.Unsetenv(key)
		}
		if len(key) > 14 && key[:14] == "TOKEN_PAYLOAD_" {
			os.Unsetenv(key)
		}
		if len(key) > 14 && key[:14] == "OAUTH_REQUEST_" {
			os.Unsetenv(key)
		}
	}
}

func TestOverrideValueWithEnvVar_EnvSet(t *testing.T) {
	os.Setenv("TEST_OVERRIDE_VAR", "env-value")
	defer os.Unsetenv("TEST_OVERRIDE_VAR")

	result := overrideValueWithEnvVar("original", "TEST_OVERRIDE_VAR")
	if result != "env-value" {
		t.Errorf("expected 'env-value', got: %s", result)
	}
}

func TestOverrideValueWithEnvVar_EnvNotSet(t *testing.T) {
	os.Unsetenv("TEST_OVERRIDE_VAR_MISSING")

	result := overrideValueWithEnvVar("original", "TEST_OVERRIDE_VAR_MISSING")
	if result != "original" {
		t.Errorf("expected 'original', got: %s", result)
	}
}

func TestOverrideValueWithEnvVar_EmptyEnv(t *testing.T) {
	os.Setenv("TEST_OVERRIDE_VAR_EMPTY", "")
	defer os.Unsetenv("TEST_OVERRIDE_VAR_EMPTY")

	result := overrideValueWithEnvVar("original", "TEST_OVERRIDE_VAR_EMPTY")
	if result != "original" {
		t.Errorf("expected 'original' for empty env var, got: %s", result)
	}
}

func TestNewConfig_FromYAMLFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-private-key"
oauth_token_url: "https://oauth.example.com/token"
oauth_response_field: "access_token"
token_header:
  kid: "yaml-kid"
token_payload:
  iss: "yaml-issuer"
  sub: "yaml-subject"
oauth_request:
  grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer"
soft_token_lifetime: 0.75
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	defer os.Unsetenv(envConfigFilePath)

	config := NewConfig()

	if config.PrivateKey != "test-private-key" {
		t.Errorf("expected private_key 'test-private-key', got: %s", config.PrivateKey)
	}
	if config.OauthTokenUrl != "https://oauth.example.com/token" {
		t.Errorf("expected oauth_token_url, got: %s", config.OauthTokenUrl)
	}
	if config.OauthResponseField != "access_token" {
		t.Errorf("expected oauth_response_field 'access_token', got: %s", config.OauthResponseField)
	}
	if config.TokenHeader["kid"] != "yaml-kid" {
		t.Errorf("expected token_header kid 'yaml-kid', got: %s", config.TokenHeader["kid"])
	}
	if config.TokenPayload["iss"] != "yaml-issuer" {
		t.Errorf("expected token_payload iss 'yaml-issuer', got: %s", config.TokenPayload["iss"])
	}
	if config.OauthRequest["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("expected oauth_request grant_type, got: %s", config.OauthRequest["grant_type"])
	}
	if config.SoftTokenLifetime != 0.75 {
		t.Errorf("expected soft_token_lifetime 0.75, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_EnvVarsOverrideYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "yaml-key"
oauth_token_url: "https://yaml.example.com/token"
oauth_response_field: "yaml_field"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	os.Setenv(envPrivateKey, "env-key")
	os.Setenv(envOauth2TokenURL, "https://env.example.com/token")
	os.Setenv(envOauth2ResponseField, "env_field")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv(envPrivateKey)
		os.Unsetenv(envOauth2TokenURL)
		os.Unsetenv(envOauth2ResponseField)
	}()

	config := NewConfig()

	if config.PrivateKey != "env-key" {
		t.Errorf("expected env var to override private_key, got: %s", config.PrivateKey)
	}
	if config.OauthTokenUrl != "https://env.example.com/token" {
		t.Errorf("expected env var to override oauth_token_url, got: %s", config.OauthTokenUrl)
	}
	if config.OauthResponseField != "env_field" {
		t.Errorf("expected env var to override oauth_response_field, got: %s", config.OauthResponseField)
	}
}

func TestNewConfig_EnvVarPrefixes(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	os.Setenv("TOKEN_HEADER_kid", "env-kid")
	os.Setenv("TOKEN_PAYLOAD_iss", "env-issuer")
	os.Setenv("OAUTH_REQUEST_scope", "openid")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv("TOKEN_HEADER_kid")
		os.Unsetenv("TOKEN_PAYLOAD_iss")
		os.Unsetenv("OAUTH_REQUEST_scope")
	}()

	config := NewConfig()

	if config.TokenHeader["kid"] != "env-kid" {
		t.Errorf("expected TOKEN_HEADER_kid='env-kid', got: %s", config.TokenHeader["kid"])
	}
	if config.TokenPayload["iss"] != "env-issuer" {
		t.Errorf("expected TOKEN_PAYLOAD_iss='env-issuer', got: %s", config.TokenPayload["iss"])
	}
	if config.OauthRequest["scope"] != "openid" {
		t.Errorf("expected OAUTH_REQUEST_scope='openid', got: %s", config.OauthRequest["scope"])
	}
}

func TestNewConfig_SoftTokenLifetimeDefault(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	defer os.Unsetenv(envConfigFilePath)

	config := NewConfig()

	if config.SoftTokenLifetime != 0.5 {
		t.Errorf("expected default soft_token_lifetime 0.5, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_SoftTokenLifetimeFromEnv(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	os.Setenv(envSoftTokenLifetime, "0.8")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv(envSoftTokenLifetime)
	}()

	config := NewConfig()

	if config.SoftTokenLifetime != 0.8 {
		t.Errorf("expected soft_token_lifetime 0.8, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_SoftTokenLifetimeOutOfRange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
soft_token_lifetime: 1.5
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	defer os.Unsetenv(envConfigFilePath)

	config := NewConfig()

	// Out of range values (< 0 or > 1) should be reset to 0.5
	if config.SoftTokenLifetime != 0.5 {
		t.Errorf("expected soft_token_lifetime reset to 0.5 for out of range, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_SoftTokenLifetimeNegative(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	os.Setenv(envSoftTokenLifetime, "-0.5")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv(envSoftTokenLifetime)
	}()

	config := NewConfig()

	// Negative values should be reset to 0.5
	if config.SoftTokenLifetime != 0.5 {
		t.Errorf("expected soft_token_lifetime reset to 0.5, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_NoConfigFile(t *testing.T) {
	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, "/nonexistent/path/config.yaml")
	os.Setenv(envPrivateKey, "test-key")
	os.Setenv(envOauth2TokenURL, "https://example.com/token")
	os.Setenv(envOauth2ResponseField, "access_token")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv(envPrivateKey)
		os.Unsetenv(envOauth2TokenURL)
		os.Unsetenv(envOauth2ResponseField)
	}()

	config := NewConfig()

	if config.PrivateKey != "test-key" {
		t.Errorf("expected private_key from env, got: %s", config.PrivateKey)
	}
}

func TestNewConfig_SoftTokenLifetimeInvalidParse(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	clearConfigEnvVars(t)
	os.Setenv(envConfigFilePath, configPath)
	os.Setenv(envSoftTokenLifetime, "not-a-number")
	defer func() {
		os.Unsetenv(envConfigFilePath)
		os.Unsetenv(envSoftTokenLifetime)
	}()

	config := NewConfig()

	// Invalid parse should keep default 0.5
	if config.SoftTokenLifetime != 0.5 {
		t.Errorf("expected soft_token_lifetime 0.5 for invalid parse, got: %f", config.SoftTokenLifetime)
	}
}

func TestNewConfig_SoftTokenLifetimeBoundary(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected float64
	}{
		{"zero", "0", 0.0},
		{"one", "1", 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			yamlContent := `
private_key: "test-key"
oauth_token_url: "https://example.com/token"
oauth_response_field: "access_token"
`
			if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}
			clearConfigEnvVars(t)
			os.Setenv(envConfigFilePath, configPath)
			os.Setenv(envSoftTokenLifetime, tt.value)
			defer func() {
				os.Unsetenv(envConfigFilePath)
				os.Unsetenv(envSoftTokenLifetime)
			}()

			config := NewConfig()
			if config.SoftTokenLifetime != tt.expected {
				t.Errorf("expected %f, got: %f", tt.expected, config.SoftTokenLifetime)
			}
		})
	}
}
