package sshlib

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/117503445/sshdev/internal/server"
	"github.com/117503445/sshdev/internal/types"
)

// internalServer is a wrapper around the internal server implementation
type internalServer struct {
	srv *server.Server
}

// newServer creates a new server with internal implementation
func newServer(cfg *Config) (Server, error) {
	internalCfg := &types.Config{
		ListenAddr:     cfg.ListenAddr,
		HostKeyPath:    cfg.HostKeyPath,
		AuthMode:       types.AuthMode(cfg.AuthMode),
		Username:       cfg.Username,
		Password:       cfg.Password,
		AuthorizedKeys: cfg.AuthorizedKeys,
		Shell:          cfg.Shell,
	}

	s, err := server.NewServer(internalCfg)
	if err != nil {
		return nil, err
	}

	return &internalServer{srv: s}, nil
}

// Start starts the SSH server
func (s *internalServer) Start() error {
	return s.srv.Start()
}

// Stop stops the SSH server gracefully
func (s *internalServer) Stop() {
	s.srv.Stop()
}

// validateConfig validates the configuration
func validateConfig(c *Config) error {
	if c.Shell == "" {
		c.Shell = "/bin/bash"
	}

	// Check password auth requirements
	if c.AuthMode == AuthModePassword || c.AuthMode == AuthModeAll {
		if c.Username == "" {
			return fmt.Errorf("%w: username is required for password authentication", ErrInvalidConfig)
		}
		if c.Password == "" && c.AuthMode == AuthModePassword {
			return fmt.Errorf("%w: password is required for password authentication", ErrInvalidConfig)
		}
	}

	// Check public key auth requirements
	if c.AuthMode == AuthModePublicKey || c.AuthMode == AuthModeAll {
		if c.AuthorizedKeys == "" {
			c.AuthorizedKeys = DefaultAuthorizedKeysPath()
		}
		if c.AuthorizedKeys == "" {
			return fmt.Errorf("%w: authorized_keys path is required for public key authentication", ErrInvalidConfig)
		}
	}

	// Check shell exists
	if _, err := os.Stat(c.Shell); err != nil {
		return fmt.Errorf("%w: shell not found: %s", ErrInvalidConfig, c.Shell)
	}

	return nil
}

// DefaultAuthorizedKeysPath returns the default path to authorized_keys
func DefaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}