package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuthMode represents the authentication mode
type AuthMode int

const (
	AuthModePassword AuthMode = iota
	AuthModePublicKey
	AuthModeNone
	AuthModeAll // Allow all configured auth methods
)

func (m AuthMode) String() string {
	switch m {
	case AuthModePassword:
		return "password"
	case AuthModePublicKey:
		return "publickey"
	case AuthModeNone:
		return "none"
	case AuthModeAll:
		return "all"
	default:
		return "unknown"
	}
}

func parseAuthMode(s string) (AuthMode, error) {
	switch strings.ToLower(s) {
	case "password":
		return AuthModePassword, nil
	case "publickey", "public_key", "pubkey":
		return AuthModePublicKey, nil
	case "none":
		return AuthModeNone, nil
	case "all":
		return AuthModeAll, nil
	default:
		return AuthModePassword, fmt.Errorf("unknown auth mode: %s", s)
	}
}

// Config holds the server configuration
type Config struct {
	ListenAddr     string
	HostKeyPath    string
	AuthMode       AuthMode
	Username       string
	Password       string
	AuthorizedKeys string
	Shell          string
}

// LoadConfig loads configuration from environment variables and command line flags
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Define flags
	flag.StringVar(&cfg.ListenAddr, "listen", getEnvOrDefault("SSHD_LISTEN", "0.0.0.0:2222"), "listen address")
	flag.StringVar(&cfg.HostKeyPath, "host-key", getEnvOrDefault("SSHD_HOST_KEY", "./host_key"), "host key file path")
	authModeStr := flag.String("auth-mode", getEnvOrDefault("SSHD_AUTH_MODE", "password"), "auth mode (password/publickey/none/all)")
	flag.StringVar(&cfg.Username, "username", getEnvOrDefault("SSHD_USERNAME", ""), "username for authentication")
	flag.StringVar(&cfg.AuthorizedKeys, "authorized-keys", getEnvOrDefault("SSHD_AUTHORIZED_KEYS", defaultAuthorizedKeysPath()), "authorized keys file path")
	flag.StringVar(&cfg.Shell, "shell", getEnvOrDefault("SSHD_SHELL", "/bin/bash"), "default shell")

	flag.Parse()

	// Password only from environment variable for security
	cfg.Password = os.Getenv("SSHD_PASSWORD")

	// Parse auth mode
	var err error
	cfg.AuthMode, err = parseAuthMode(*authModeStr)
	if err != nil {
		return nil, err
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Check password auth requirements
	if c.AuthMode == AuthModePassword || c.AuthMode == AuthModeAll {
		if c.Username == "" {
			return fmt.Errorf("username is required for password authentication (set SSHD_USERNAME)")
		}
		if c.Password == "" && c.AuthMode == AuthModePassword {
			return fmt.Errorf("password is required for password authentication (set SSHD_PASSWORD)")
		}
	}

	// Check public key auth requirements
	if c.AuthMode == AuthModePublicKey || c.AuthMode == AuthModeAll {
		if c.AuthorizedKeys == "" {
			return fmt.Errorf("authorized_keys path is required for public key authentication")
		}
	}

	// Check shell exists
	if _, err := os.Stat(c.Shell); err != nil {
		return fmt.Errorf("shell not found: %s", c.Shell)
	}

	return nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func defaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}
