package sshlib

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"

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
	log.Info().Msg("Validating configuration")

	// Determine shell
	if c.Shell == "" {
		c.Shell = "/bin/sh"
		if shell := os.Getenv("SHELL"); shell != "" {
			log.Info().Str("envShell", shell).Msg("Using SHELL environment variable")
			c.Shell = shell
		}
	}

	log.Info().Str("shell", c.Shell).Msg("Checking if shell exists")

	// Check shell exists
	// On Windows, if shell is just a filename (like "cmd.exe"), we need to look it up in PATH
	if runtime.GOOS == "windows" && !filepath.IsAbs(c.Shell) && !containsPathSeparator(c.Shell) {
		// Try to find the executable in PATH
		if fullPath, err := exec.LookPath(c.Shell); err == nil {
			log.Info().Str("shell", c.Shell).Str("fullPath", fullPath).Msg("Found shell in PATH")
			c.Shell = fullPath
		} else {
			log.Warn().Err(err).Str("shell", c.Shell).Msg("Shell not found in PATH, will try as-is")
		}
	}

	stat, err := os.Stat(c.Shell)
	if err != nil {
		log.Error().Err(err).Str("shell", c.Shell).Msg("Shell not found or not accessible")
		return fmt.Errorf("%w: shell not found: %s (error: %v)", ErrInvalidConfig, c.Shell, err)
	}

	if stat.IsDir() {
		log.Error().Str("shell", c.Shell).Msg("Shell path is a directory, not a file")
		return fmt.Errorf("%w: shell path is a directory: %s", ErrInvalidConfig, c.Shell)
	}

	log.Info().Str("shell", c.Shell).Msg("Shell validated successfully")
	return nil
}

// containsPathSeparator checks if the path contains any path separator
func containsPathSeparator(path string) bool {
	return contains(path, '/') || contains(path, '\\')
}

// contains checks if s contains c
func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// DefaultAuthorizedKeysPath returns the default path to authorized_keys
func DefaultAuthorizedKeysPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "authorized_keys")
}