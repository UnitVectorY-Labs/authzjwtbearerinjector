package internal

import (
	"log"
	"os"
)

const (
	// environment variable names
	envDebug = "DEBUG"
)

var (
	debugLogEnabled bool
)

// Function for debug logging
func DebugLog(message string, v ...any) {
	if debugLogEnabled {
		log.Printf(message, v...)
	}
}

// Function to check if debug logging is enabled
func IsDebugLogEnabled() bool {
	return debugLogEnabled
}

func init() {
	// Check if DEBUG logging is enabled via an environment variable
	debugLogEnabled = os.Getenv(envDebug) == "true"
}
