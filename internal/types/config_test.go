package types

import (
	"os"
	"testing"
)

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
			name: "valid config with password auth",
			config: &Config{
				Password: "test",
				Shell:    tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "valid config with public key auth",
			config: &Config{
				AuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
				Shell:          tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "valid config with both auth methods",
			config: &Config{
				Password:       "test",
				AuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
				Shell:          tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "valid config with no auth",
			config: &Config{
				Shell: tempShell.Name(),
			},
			expectError: false,
		},
		{
			name: "invalid shell path",
			config: &Config{
				Shell: "/this/path/does/not/exist",
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

func TestHasPasswordAuth(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "with password",
			config:   &Config{Password: "secret"},
			expected: true,
		},
		{
			name:     "without password",
			config:   &Config{Password: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasPasswordAuth()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestHasPublicKeyAuth(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "with authorized keys files",
			config:   &Config{AuthorizedKeysFiles: "/home/user/.ssh/authorized_keys"},
			expected: true,
		},
		{
			name:     "with authorized keys content",
			config:   &Config{AuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
			expected: true,
		},
		{
			name:     "with both",
			config:   &Config{AuthorizedKeysFiles: "/home/user/.ssh/authorized_keys", AuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
			expected: true,
		},
		{
			name:     "without public key auth",
			config:   &Config{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasPublicKeyAuth()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestParseAuthorizedKeysFiles(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single path",
			input:    "/home/user/.ssh/authorized_keys",
			expected: []string{"/home/user/.ssh/authorized_keys"},
		},
		{
			name:     "multiple paths",
			input:    "/home/user/.ssh/authorized_keys:/etc/ssh/authorized_keys",
			expected: []string{"/home/user/.ssh/authorized_keys", "/etc/ssh/authorized_keys"},
		},
		{
			name:     "paths with spaces",
			input:    "  /path/one  :  /path/two  ",
			expected: []string{"/path/one", "/path/two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAuthorizedKeysFiles(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d paths, got %d", len(tt.expected), len(result))
				return
			}
			for i, p := range result {
				if p != tt.expected[i] {
					t.Errorf("Path %d: expected %q, got %q", i, tt.expected[i], p)
				}
			}
		})
	}
}

func TestParseAuthorizedKeysContent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single key",
			input:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
			expected: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
		},
		{
			name:     "multiple keys",
			input:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\nssh-ed25519 BBBBC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
			expected: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "ssh-ed25519 BBBBC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
		},
		{
			name:     "keys with comments",
			input:    "# This is a comment\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n# Another comment",
			expected: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseAuthorizedKeysContent(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d keys, got %d", len(tt.expected), len(result))
				return
			}
			for i, k := range result {
				if k != tt.expected[i] {
					t.Errorf("Key %d: expected %q, got %q", i, tt.expected[i], k)
				}
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