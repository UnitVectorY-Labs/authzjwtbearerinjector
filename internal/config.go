package internal

import (
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// environment variable names
	envConfigFilePath      = "CONFIG_FILE_PATH"
	envSoftTokenLifetime   = "SOFT_TOKEN_LIFETIME"
	envPrivateKey          = "PRIVATE_KEY"
	envPrivateKeyId        = "PRIVATE_KEY_ID"
	envOauth2TokenURL      = "OAUTH2_TOKEN_URL"
	envOauth2ResponseField = "OAUTH2_RESPONSE_FIELD"
	envOauth2ClientId      = "OAUTH2_CLIENT_ID"
	envOauth2Audience      = "OAUTH2_AUDIENCE"
)

type Config struct {
	PrivateKey   string            `yaml:"private_key"`
	PrivateKeyId string            `yaml:"private_key_id"`
	LocalToken   map[string]string `yaml:"local_token"`
	Oauth2       struct {
		TokenURL      string `yaml:"token_url"`
		ResponseField string `yaml:"response_field"`
		ClientId      string `yaml:"client_id"`
		Audience      string `yaml:"audience"`
	} `yaml:"oauth2"`
	SoftTokenLifetime float64 `yaml:"soft_token_lifetime"`
}

// NewConfig is a constructor function that creates and returns a new Config struct
func NewConfig() *Config {
	config := &Config{
		LocalToken: make(map[string]string),
	}

	// Determine the config file path
	configFilePath := os.Getenv(envConfigFilePath)
	if configFilePath == "" {
		configFilePath = "/app/config.yaml"
	}

	// Load in the configuration for the config file if it exists
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		// It doesn't exist, that is ok, it could be set in the environment variables
		log.Printf("config file does not exist: %v", err)
		log.Print("no config file found, using environment variables only")
	} else {
		// It exists, read the file and unmarshal it
		configFileContent, err := os.ReadFile(configFilePath)
		if err != nil {
			log.Fatalf("failed to read config file: %v", err)
		}

		err = yaml.Unmarshal(configFileContent, &config)
		if err != nil {
			log.Fatalf("failed to unmarshal config file: %v", err)
		}
	}

	// Parse the private key from the environment variables
	envValPrivateKey := os.Getenv(envPrivateKey)
	if envValPrivateKey != "" {
		config.PrivateKey = envValPrivateKey
	}

	// Parse the private key id from the environment variables
	envValPrivateKeyId := os.Getenv(envPrivateKeyId)
	if envValPrivateKeyId != "" {
		config.PrivateKeyId = envValPrivateKeyId
	}

	// Loop through all of the environment variables grabbing the LOCAL_TOKEN_ variables
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		key := pair[0]
		value := pair[1]

		// If the variable starts with LOCAL_TOKEN_, overwrite the value from the config file
		if strings.HasPrefix(key, "LOCAL_TOKEN_") {
			config.LocalToken[strings.TrimPrefix(key, "LOCAL_TOKEN_")] = value
		}
	}

	// Parse the oauth2 token url from the environment variables
	envValOauth2TokenURL := os.Getenv(envOauth2TokenURL)
	if envValOauth2TokenURL != "" {
		config.Oauth2.TokenURL = envValOauth2TokenURL
	}

	// Parse the oauth2 response field from the environment variables
	envValOauth2ResponseField := os.Getenv(envOauth2ResponseField)
	if envValOauth2ResponseField != "" {
		config.Oauth2.ResponseField = envValOauth2ResponseField
	}

	// Parse the oauth2 client id from the environment variables
	envValOauth2ClientId := os.Getenv(envOauth2ClientId)
	if envValOauth2ClientId != "" {
		config.Oauth2.ClientId = envValOauth2ClientId
	}

	// Parse the oauth2 audience from the environment variables
	envValOauth2Audience := os.Getenv(envOauth2Audience)
	if envValOauth2Audience != "" {
		config.Oauth2.Audience = envValOauth2Audience
	}

	// Parse the soft token lifetime from the environment variables
	envValSoftTokenLifetime := os.Getenv(envSoftTokenLifetime)
	if envValSoftTokenLifetime != "" {

		tokenSoftLifetimeParsed, err := strconv.ParseFloat(envValSoftTokenLifetime, 32)
		if err != nil {
			log.Printf("failed to parse SOFT_TOKEN_LIFETIME: %v", err)
		}
		config.SoftTokenLifetime = tokenSoftLifetimeParsed
	}

	// Enforce that SoftTokenLifetime is beteen 0 and 1
	if config.SoftTokenLifetime < 0 || config.SoftTokenLifetime > 1 {
		config.SoftTokenLifetime = 0.5
	}

	// Log the configuration if debug logging is enabled
	if debugLogEnabled {
		DebugLog("Config - Private Key ID: %s", config.PrivateKeyId)

		for k, v := range config.LocalToken {
			DebugLog("Config - Local Token: %s = %s", k, v)
		}
		DebugLog("Config - OAuth2 Token URL: %s", config.Oauth2.TokenURL)
		DebugLog("Config - OAuth2 Response Field: %s", config.Oauth2.ResponseField)
		DebugLog("Config - OAuth2 Client ID: %s", config.Oauth2.ClientId)
		DebugLog("Config - OAuth2 Audience: %s", config.Oauth2.Audience)
		DebugLog("Config - Soft Token Lifetime: %f", config.SoftTokenLifetime)
	}

	return config
}
