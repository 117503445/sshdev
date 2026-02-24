package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Authenticator handles SSH authentication
type Authenticator struct {
	cfg            *Config
	authorizedKeys []ssh.PublicKey
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(cfg *Config) (*Authenticator, error) {
	auth := &Authenticator{cfg: cfg}

	// Load authorized keys if needed
	if cfg.AuthMode == AuthModePublicKey || cfg.AuthMode == AuthModeAll {
		if err := auth.loadAuthorizedKeys(); err != nil {
			// Only error if publickey is the only auth mode
			if cfg.AuthMode == AuthModePublicKey {
				return nil, fmt.Errorf("failed to load authorized keys: %w", err)
			}
			log.Printf("[WARN] Failed to load authorized keys: %v", err)
		}
	}

	return auth, nil
}

// loadAuthorizedKeys loads public keys from the authorized_keys file
func (a *Authenticator) loadAuthorizedKeys() error {
	file, err := os.Open(a.cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse public key
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			log.Printf("[WARN] Failed to parse authorized key at line %d: %v", lineNum, err)
			continue
		}

		a.authorizedKeys = append(a.authorizedKeys, pubKey)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Printf("[INFO] Loaded %d authorized keys from %s", len(a.authorizedKeys), a.cfg.AuthorizedKeys)
	return nil
}

// PasswordCallback returns the password authentication callback
func (a *Authenticator) PasswordCallback() func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	if a.cfg.AuthMode == AuthModeNone {
		return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("[INFO] Auth success (no-auth mode): user=%s client=%s", c.User(), c.RemoteAddr())
			return nil, nil
		}
	}

	if a.cfg.AuthMode != AuthModePassword && a.cfg.AuthMode != AuthModeAll {
		return nil
	}

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == a.cfg.Username && string(pass) == a.cfg.Password {
			log.Printf("[INFO] Auth success: user=%s method=password client=%s", c.User(), c.RemoteAddr())
			return nil, nil
		}
		log.Printf("[WARN] Auth failed: user=%s method=password client=%s", c.User(), c.RemoteAddr())
		return nil, fmt.Errorf("authentication failed")
	}
}

// PublicKeyCallback returns the public key authentication callback
func (a *Authenticator) PublicKeyCallback() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	if a.cfg.AuthMode == AuthModeNone {
		return func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("[INFO] Auth success (no-auth mode): user=%s client=%s", c.User(), c.RemoteAddr())
			return nil, nil
		}
	}

	if a.cfg.AuthMode != AuthModePublicKey && a.cfg.AuthMode != AuthModeAll {
		return nil
	}

	if len(a.authorizedKeys) == 0 {
		return nil
	}

	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyBytes := key.Marshal()
		for _, authorizedKey := range a.authorizedKeys {
			if bytes.Equal(keyBytes, authorizedKey.Marshal()) {
				log.Printf("[INFO] Auth success: user=%s method=publickey client=%s", c.User(), c.RemoteAddr())
				return nil, nil
			}
		}
		log.Printf("[WARN] Auth failed: user=%s method=publickey client=%s", c.User(), c.RemoteAddr())
		return nil, fmt.Errorf("authentication failed")
	}
}

// NoClientAuthCallback returns the no-auth callback for none mode
func (a *Authenticator) NoClientAuthCallback() func(ssh.ConnMetadata) (*ssh.Permissions, error) {
	if a.cfg.AuthMode != AuthModeNone {
		return nil
	}

	return func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
		log.Printf("[INFO] Auth success (no-auth mode): user=%s client=%s", c.User(), c.RemoteAddr())
		return nil, nil
	}
}
