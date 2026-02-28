package sshlib

import (
	"context"
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
		ListenAddr:           cfg.ListenAddr,
		HostKeyPath:          cfg.HostKeyPath,
		HostKeyContent:       cfg.HostKeyContent,
		HostKeyBuiltin:       cfg.HostKeyBuiltin,
		Password:             cfg.Password,
		AuthorizedKeysFiles:  cfg.AuthorizedKeysFiles,
		AuthorizedKeys:       cfg.AuthorizedKeys,
		Shell:                cfg.Shell,
		DisablePortForward:   cfg.DisablePortForward,
		DisableRemoteForward: cfg.DisableRemoteForward,
	}

	s, err := server.NewServer(internalCfg)
	if err != nil {
		return nil, err
	}

	return &internalServer{srv: s}, nil
}

// Start starts the SSH server
func (s *internalServer) Start(ctx context.Context) error {
	return s.srv.Start(ctx)
}

// Stop stops the SSH server gracefully
func (s *internalServer) Stop() {
	s.srv.Stop()
}

// validateConfig validates the configuration
func validateConfig(c *Config) error {
	// Determine shell
	if c.Shell == "" {
		c.Shell = "/bin/sh"
		if shell := os.Getenv("SHELL"); shell != "" {
			c.Shell = shell
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