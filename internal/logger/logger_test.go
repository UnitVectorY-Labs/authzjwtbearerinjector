package logger

import (
	"bytes"
	"log"
	"os"
	"testing"
)

func TestIsDebugLogEnabled_DefaultFalse(t *testing.T) {
	original := debugLogEnabled
	defer func() { debugLogEnabled = original }()

	debugLogEnabled = false
	if IsDebugLogEnabled() {
		t.Error("expected IsDebugLogEnabled() to return false when debug is disabled")
	}
}

func TestIsDebugLogEnabled_True(t *testing.T) {
	original := debugLogEnabled
	defer func() { debugLogEnabled = original }()

	debugLogEnabled = true
	if !IsDebugLogEnabled() {
		t.Error("expected IsDebugLogEnabled() to return true when debug is enabled")
	}
}

func TestDebugLog_DisabledNoOutput(t *testing.T) {
	original := debugLogEnabled
	defer func() { debugLogEnabled = original }()

	debugLogEnabled = false

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	DebugLog("should not appear %s", "test")

	if buf.Len() != 0 {
		t.Errorf("expected no output when debug is disabled, got: %s", buf.String())
	}
}

func TestDebugLog_EnabledOutputs(t *testing.T) {
	original := debugLogEnabled
	defer func() { debugLogEnabled = original }()

	debugLogEnabled = true

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	DebugLog("hello %s", "world")

	output := buf.String()
	if output == "" {
		t.Error("expected output when debug is enabled, got nothing")
	}
	if !bytes.Contains(buf.Bytes(), []byte("hello world")) {
		t.Errorf("expected output to contain 'hello world', got: %s", output)
	}
}

// TestInit_SetsDebugLogFromEnv verifies the logic used by init() to read DEBUG env var.
// Go's init() cannot be re-invoked, so we replicate its logic here.
func TestInit_SetsDebugLogFromEnv(t *testing.T) {
	original := debugLogEnabled
	originalEnv, envWasSet := os.LookupEnv("DEBUG")
	defer func() {
		debugLogEnabled = original
		if envWasSet {
			os.Setenv("DEBUG", originalEnv)
		} else {
			os.Unsetenv("DEBUG")
		}
	}()

	os.Setenv("DEBUG", "true")
	// Re-run the init logic manually
	debugLogEnabled = os.Getenv("DEBUG") == "true"
	if !IsDebugLogEnabled() {
		t.Error("expected debug to be enabled when DEBUG=true")
	}

	os.Setenv("DEBUG", "false")
	debugLogEnabled = os.Getenv("DEBUG") == "true"
	if IsDebugLogEnabled() {
		t.Error("expected debug to be disabled when DEBUG=false")
	}

	os.Unsetenv("DEBUG")
	debugLogEnabled = os.Getenv("DEBUG") == "true"
	if IsDebugLogEnabled() {
		t.Error("expected debug to be disabled when DEBUG is unset")
	}
}
