package sshlib

import (
	"errors"
)

// Server represents an SSH server
type Server interface {
	// Start starts the SSH server
	Start() error
	// Stop stops the SSH server gracefully
	Stop()
}

// NewServer creates a new SSH server with the given configuration
func NewServer(cfg *Config) (Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return newServer(cfg)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	return validateConfig(c)
}

var (
	// ErrInvalidConfig is returned when the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrAuthenticationFailed is returned when authentication fails
	ErrAuthenticationFailed = errors.New("authentication failed")
)