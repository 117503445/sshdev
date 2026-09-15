package auth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/internal/types"
)

// Authenticator handles SSH authentication
type Authenticator struct {
	cfg         *types.Config
	contentKeys []ssh.PublicKey
	ctx         context.Context
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(cfg *types.Config) (*Authenticator, error) {
	return NewAuthenticatorWithContext(context.Background(), cfg)
}

// NewAuthenticatorWithContext creates a new authenticator with context
func NewAuthenticatorWithContext(ctx context.Context, cfg *types.Config) (*Authenticator, error) {
	auth := &Authenticator{cfg: cfg, ctx: ctx}

	// Load authorized keys if public key auth is enabled
	if cfg.HasPublicKeyAuth() {
		if err := auth.loadAuthorizedKeys(ctx); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to load authorized keys")
		}
	}

	return auth, nil
}

// loadAuthorizedKeys loads public keys from content, and probes key files once
// to surface configuration errors early. File-sourced keys are re-read on every
// authentication attempt so external updates (e.g. sshole agent appending a
// known host key) take effect without restarting the server.
func (a *Authenticator) loadAuthorizedKeys(ctx context.Context) error {
	// Load from content
	if a.cfg.AuthorizedKeys != "" {
		lines := types.ParseAuthorizedKeysContent(a.cfg.AuthorizedKeys)
		for _, line := range lines {
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				log.Ctx(ctx).Warn().Err(err).Str("line", line).Msg("failed to parse authorized key from content")
				continue
			}
			a.contentKeys = append(a.contentKeys, pubKey)
		}
	}

	// Probe files once at startup; the parsed result is not cached.
	fileCount := 0
	if a.cfg.AuthorizedKeysFiles != "" {
		fileCount = len(a.loadFileKeys(ctx))
	}

	log.Ctx(ctx).Info().Int("content", len(a.contentKeys)).Int("files", fileCount).Msg("loaded authorized keys")
	return nil
}

// loadFileKeys reads and parses all configured authorized keys files.
func (a *Authenticator) loadFileKeys(ctx context.Context) []ssh.PublicKey {
	var keys []ssh.PublicKey
	paths := types.ParseAuthorizedKeysFiles(a.cfg.AuthorizedKeysFiles)
	for _, path := range paths {
		fileKeys, err := loadAuthorizedKeysFromFile(ctx, path)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("path", path).Msg("failed to load authorized keys from file")
			continue
		}
		keys = append(keys, fileKeys...)
	}
	return keys
}

// loadAuthorizedKeysFromFile loads public keys from a single file
func loadAuthorizedKeysFromFile(ctx context.Context, path string) ([]ssh.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var keys []ssh.PublicKey
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

		keys = append(keys, pubKey)
	}

	return keys, scanner.Err()
}

// PasswordCallback returns the password authentication callback
func (a *Authenticator) PasswordCallback() func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	if !a.cfg.HasPasswordAuth() {
		return nil
	}

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if string(pass) == a.cfg.Password {
			log.Ctx(a.ctx).Info().Str("user", c.User()).Str("method", "password").Str("client", c.RemoteAddr().String()).Msg("auth success")
			return nil, nil
		}
		log.Ctx(a.ctx).Warn().Str("user", c.User()).Str("method", "password").Str("client", c.RemoteAddr().String()).Msg("auth failed")
		return nil, fmt.Errorf("authentication failed")
	}
}

// PublicKeyCallback returns the public key authentication callback
func (a *Authenticator) PublicKeyCallback() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	if !a.cfg.HasPublicKeyAuth() {
		return nil
	}

	return func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Content keys are fixed at startup; file keys are re-read on every
		// authentication attempt so newly appended keys take effect without
		// restarting the server.
		keys := make([]ssh.PublicKey, 0, len(a.contentKeys))
		keys = append(keys, a.contentKeys...)
		if a.cfg.AuthorizedKeysFiles != "" {
			keys = append(keys, a.loadFileKeys(a.ctx)...)
		}

		keyBytes := key.Marshal()
		for _, authorizedKey := range keys {
			if string(keyBytes) == string(authorizedKey.Marshal()) {
				log.Ctx(a.ctx).Info().Str("user", c.User()).Str("method", "publickey").Str("client", c.RemoteAddr().String()).Msg("auth success")
				return nil, nil
			}
		}
		log.Ctx(a.ctx).Warn().Str("user", c.User()).Str("method", "publickey").Str("client", c.RemoteAddr().String()).Msg("auth failed")
		return nil, fmt.Errorf("authentication failed")
	}
}

// NoClientAuthCallback 返回无认证回调
// 仅当未配置密码和公钥且显式启用 insecure 时允许无认证
func (a *Authenticator) NoClientAuthCallback() func(ssh.ConnMetadata) (*ssh.Permissions, error) {
	if a.cfg.HasPasswordAuth() || a.cfg.HasPublicKeyAuth() || !a.cfg.Insecure {
		return nil
	}

	return func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
		log.Ctx(a.ctx).Info().Str("user", c.User()).Str("client", c.RemoteAddr().String()).Msg("auth success (no-auth mode)")
		return nil, nil
	}
}
