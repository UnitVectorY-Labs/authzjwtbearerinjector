package internal

import (
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// Environment Variable names
	envConfigFilePath      = "CONFIG_FILE_PATH"
	envPrivateKey          = "PRIVATE_KEY"
	envOauth2TokenURL      = "OAUTH2_TOKEN_URL"
	envOauth2ResponseField = "OAUTH2_RESPONSE_FIELD"
	envSoftTokenLifetime   = "SOFT_TOKEN_LIFETIME"

	// Environment Variables Prefixes
	envTokenHeaderPrefix  = "TOKEN_HEADER_"
	envTokenPayloadPrefix = "TOKEN_PAYLOAD_"
	envOauthRequestPrefix = "OAUTH_REQUEST_"
)

type Config struct {
	PrivateKey string `yaml:"private_key"`

	// Environment Variable prefix TOKEN_HEADER_
	TokenHeader map[string]string `yaml:"token_header"`

	// Environment Variable prefix TOKEN_PAYLOAD_
	TokenPayload map[string]string `yaml:"token_payload"`

	// Environment Variable prefix OAUTH_REQUEST_
	OauthRequest map[string]string `yaml:"oauth_request"`

	OauthTokenUrl      string  `yaml:"oauth_token_url"`
	OauthResponseField string  `yaml:"oauth_response_field"`
	SoftTokenLifetime  float64 `yaml:"soft_token_lifetime"`
}

// NewConfig is a constructor function that creates and returns a new Config struct
func NewConfig() *Config {
	config := &Config{
		TokenHeader:       make(map[string]string),
		TokenPayload:      make(map[string]string),
		OauthRequest:      make(map[string]string),
		SoftTokenLifetime: 0.5,
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

	config.PrivateKey = overrideValueWithEnvVar(config.PrivateKey, envPrivateKey)

	// Loop through all of the environment variables grabbing the pattern variables
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		key := pair[0]
		value := pair[1]

		if strings.HasPrefix(key, envTokenHeaderPrefix) {
			config.TokenHeader[strings.TrimPrefix(key, envTokenHeaderPrefix)] = value
		} else if strings.HasPrefix(key, envTokenPayloadPrefix) {
			config.TokenPayload[strings.TrimPrefix(key, envTokenPayloadPrefix)] = value
		} else if strings.HasPrefix(key, envOauthRequestPrefix) {
			config.OauthRequest[strings.TrimPrefix(key, envOauthRequestPrefix)] = value
		}
	}

	config.OauthTokenUrl = overrideValueWithEnvVar(config.OauthTokenUrl, envOauth2TokenURL)
	config.OauthResponseField = overrideValueWithEnvVar(config.OauthResponseField, envOauth2ResponseField)

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

		for k, v := range config.TokenHeader {
			DebugLog("Config - Token Header: %s = %s", k, v)
		}

		for k, v := range config.TokenPayload {
			DebugLog("Config - Token Payload: %s = %s", k, v)
		}

		for k, v := range config.OauthRequest {
			DebugLog("Config - OAuth2 Request: %s = %s", k, v)
		}

		DebugLog("Config - OAuth2 Token URL: %s", config.OauthTokenUrl)
		DebugLog("Config - Soft Token Lifetime: %f", config.SoftTokenLifetime)
	}

	// Make sure the required components are set otherwise panic
	if config.PrivateKey == "" {
		log.Fatal("private_key is required")
	} else if config.OauthTokenUrl == "" {
		log.Fatal("oauth_token_url is required")
	} else if config.OauthResponseField == "" {
		log.Fatal("oauth_response_field is required")
	}

	return config
}

// Override value with environment variable if it exists
func overrideValueWithEnvVar(currentValue string, envVarName string) string {
	envVar := os.Getenv(envVarName)
	if envVar != "" {
		return envVar
	} else {
		return currentValue
	}
}
