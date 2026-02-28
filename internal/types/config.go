package types

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds the server configuration
type Config struct {
	ListenAddr           string
	HostKeyPath          string // Path to host key file (command line arg)
	HostKeyContent       string // Host key content (from env SSHDEV_HOST_KEY)
	HostKeyBuiltin       bool   // Use built-in host key (from env SSHDEV_HOST_KEY_BUILTIN)
	Password             string // Password for authentication (from env SSHDEV_PASSWORD)
	AuthorizedKeysFiles  string // Authorized keys file paths, colon-separated (from env SSHDEV_AUTHORIZED_KEYS_FILES)
	AuthorizedKeys       string // Authorized keys content, newline-separated (from env SSHDEV_AUTHORIZED_KEYS)
	Shell                string // Shell to use (from env SSHDEV_SHELL, empty = current user's default)
	DisablePortForward   bool   // Disable local port forwarding (direct-tcpip), default: enabled
	DisableRemoteForward bool   // Disable remote port forwarding (tcpip-forward), default: enabled
}

// HasPasswordAuth returns true if password authentication is enabled
func (c *Config) HasPasswordAuth() bool {
	return c.Password != ""
}

// HasPublicKeyAuth returns true if public key authentication is enabled
func (c *Config) HasPublicKeyAuth() bool {
	return c.AuthorizedKeysFiles != "" || c.AuthorizedKeys != ""
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Determine shell
	if c.Shell == "" {
		c.Shell = getDefaultShell()
	}

	// Check shell exists
	if _, err := os.Stat(c.Shell); err != nil {
		return fmt.Errorf("shell not found: %s", c.Shell)
	}

	return nil
}

// getDefaultShell returns the current user's default shell
func getDefaultShell() string {
	// Check SHELL env var first
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	// Fallback
	return "/bin/sh"
}

// ParseAuthorizedKeysFiles parses the colon-separated authorized keys file paths
func ParseAuthorizedKeysFiles(paths string) []string {
	if paths == "" {
		return nil
	}
	var result []string
	for _, p := range strings.Split(paths, ":") {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ParseAuthorizedKeysContent parses the newline-separated authorized keys content
func ParseAuthorizedKeysContent(content string) []string {
	if content == "" {
		return nil
	}
	var result []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}

func DefaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}