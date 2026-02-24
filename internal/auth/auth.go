package auth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/dev-sshd/internal/types"
)

// Authenticator handles SSH authentication
type Authenticator struct {
	cfg            *types.Config
	authorizedKeys []ssh.PublicKey
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(cfg *types.Config) (*Authenticator, error) {
	auth := &Authenticator{cfg: cfg}

	// Load authorized keys if needed
	if cfg.AuthMode == types.AuthModePublicKey || cfg.AuthMode == types.AuthModeAll {
		if err := auth.loadAuthorizedKeys(context.Background()); err != nil {
			// Only error if publickey is the only auth mode
			if cfg.AuthMode == types.AuthModePublicKey {
				return nil, fmt.Errorf("failed to load authorized keys: %w", err)
			}
			log.Warn().Err(err).Msg("failed to load authorized keys")
		}
	}

	return auth, nil
}

// loadAuthorizedKeys loads public keys from the authorized_keys file
func (a *Authenticator) loadAuthorizedKeys(ctx context.Context) error {
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
			log.Ctx(ctx).Warn().Err(err).Int("line", lineNum).Msg("failed to parse authorized key")
			continue
		}

		a.authorizedKeys = append(a.authorizedKeys, pubKey)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	log.Ctx(ctx).Info().Int("count", len(a.authorizedKeys)).Str("path", a.cfg.AuthorizedKeys).Msg("loaded authorized keys")
	return nil
}

// PasswordCallback returns the password authentication callback
func (a *Authenticator) PasswordCallback() func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	if a.cfg.AuthMode == types.AuthModeNone {
		return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Info().Str("user", c.User()).Str("client", c.RemoteAddr().String()).Msg("auth success (no-auth mode)")
			return nil, nil
		}
	}

	if a.cfg.AuthMode != types.AuthModePassword && a.cfg.AuthMode != types.AuthModeAll {
		return nil
	}

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == a.cfg.Username && string(pass) == a.cfg.Password {
			log.Info().Str("user", c.User()).Str("method", "password").Str("client", c.RemoteAddr().String()).Msg("auth success")
			return nil, nil
		}
		log.Warn().Str("user", c.User()).Str("method", "password").Str("client", c.RemoteAddr().String()).Msg("auth failed")
		return nil, fmt.Errorf("authentication failed")
	}
}

// PublicKeyCallback returns the public key authentication callback
func (a *Authenticator) PublicKeyCallback() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	if a.cfg.AuthMode == types.AuthModeNone {
		return func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Info().Str("user", c.User()).Str("client", c.RemoteAddr().String()).Msg("auth success (no-auth mode)")
			return nil, nil
		}
	}

	if a.cfg.AuthMode != types.AuthModePublicKey && a.cfg.AuthMode != types.AuthModeAll {
		return nil
	}

	if len(a.authorizedKeys) == 0 {
		return nil
	}

	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyBytes := key.Marshal()
		for _, authorizedKey := range a.authorizedKeys {
			if string(keyBytes) == string(authorizedKey.Marshal()) {
				log.Info().Str("user", c.User()).Str("method", "publickey").Str("client", c.RemoteAddr().String()).Msg("auth success")
				return nil, nil
			}
		}
		log.Warn().Str("user", c.User()).Str("method", "publickey").Str("client", c.RemoteAddr().String()).Msg("auth failed")
		return nil, fmt.Errorf("authentication failed")
	}
}

// NoClientAuthCallback returns the no-auth callback for none mode
func (a *Authenticator) NoClientAuthCallback() func(ssh.ConnMetadata) (*ssh.Permissions, error) {
	if a.cfg.AuthMode != types.AuthModeNone {
		return nil
	}

	return func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
		log.Info().Str("user", c.User()).Str("client", c.RemoteAddr().String()).Msg("auth success (no-auth mode)")
		return nil, nil
	}
}