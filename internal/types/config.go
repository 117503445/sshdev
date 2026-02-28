package types

import (
	"fmt"
	"os"
	"path/filepath"
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

// Config holds the server configuration
type Config struct {
	ListenAddr           string
	HostKeyPath          string
	AuthMode             AuthMode
	Username             string
	Password             string
	AuthorizedKeys       string
	Shell                string
	DisablePortForward   bool // Disable local port forwarding (direct-tcpip), default: enabled
	DisableRemoteForward bool // Disable remote port forwarding (tcpip-forward), default: enabled
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Check password auth requirements
	if c.AuthMode == AuthModePassword || c.AuthMode == AuthModeAll {
		if c.Username == "" {
			return fmt.Errorf("username is required for password authentication (set SSHDEV_USERNAME)")
		}
		if c.Password == "" && c.AuthMode == AuthModePassword {
			return fmt.Errorf("password is required for password authentication (set SSHDEV_PASSWORD)")
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

func DefaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}
