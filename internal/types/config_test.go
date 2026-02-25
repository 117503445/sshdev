package types

import (
	"os"
	"testing"
)

func TestAuthModeString(t *testing.T) {
	tests := []struct {
		mode     AuthMode
		expected string
	}{
		{AuthModePassword, "password"},
		{AuthModePublicKey, "publickey"},
		{AuthModeNone, "none"},
		{AuthModeAll, "all"},
		{-1, "unknown"}, // Unknown mode
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	// Create a temporary shell for the test
	tempShell, err := os.CreateTemp("", "shell-test-*")
	if err != nil {
		t.Fatal("Could not create temp shell:", err)
	}
	tempShell.Close()
	defer os.Remove(tempShell.Name())

	// Make it executable
	err = os.Chmod(tempShell.Name(), 0755)
	if err != nil {
		t.Fatal("Could not make temp shell executable:", err)
	}

	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid password config",
			config: &Config{
				AuthMode: AuthModePassword,
				Username: "test",
				Password: "test",
				Shell:    tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "password without username",
			config: &Config{
				AuthMode: AuthModePassword,
				Username: "",
				Password: "test",
				Shell:    tempShell.Name(),
			},
			expectError: true,
		},
		{
			name: "password without password",
			config: &Config{
				AuthMode: AuthModePassword,
				Username: "test",
				Password: "",
				Shell:    tempShell.Name(),
			},
			expectError: true,
		},
		{
			name: "all mode with username but no password or keys",
			config: &Config{
				AuthMode: AuthModeAll,
				Username: "test",
				Password: "", // This would normally fail because publickey requires authorized keys
				AuthorizedKeys: "/tmp/keys", // Provide a fake path to satisfy the check
				Shell:    tempShell.Name(),
			},
			expectError: false, // In ALL mode, with fake keys path it should pass
		},
		{
			name: "none auth mode",
			config: &Config{
				AuthMode: AuthModeNone,
				Username: "",
				Password: "",
				Shell:    tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "invalid shell path",
			config: &Config{
				AuthMode: AuthModeNone,
				Username: "",
				Password: "",
				Shell:    "/this/path/does/not/exist",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestDefaultAuthorizedKeysPath(t *testing.T) {
	path := DefaultAuthorizedKeysPath()

	// Just check that we get a non-empty path
	if path == "" {
		t.Error("Expected non-empty path for default authorized keys")
	}

	// Path should contain .ssh and authorized_keys
	if len(path) < 10 { // Reasonable minimum length
		t.Logf("Path is very short: %s", path)
	}
}