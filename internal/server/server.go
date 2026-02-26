package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/internal/auth"
	"github.com/117503445/sshdev/internal/session"
	"github.com/117503445/sshdev/internal/types"
)

// Server represents the SSH server
type Server struct {
	cfg      *types.Config
	sshCfg   *ssh.ServerConfig
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
}

// NewServer creates a new SSH server
func NewServer(cfg *types.Config) (*Server, error) {
	s := &Server{
		cfg:  cfg,
		quit: make(chan struct{}),
	}

	// Load or generate host key
	hostKey, err := s.loadOrGenerateHostKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}

	// Create authenticator
	auth, err := auth.NewAuthenticator(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Create SSH server config
	s.sshCfg = &ssh.ServerConfig{}
	s.sshCfg.AddHostKey(hostKey)

	// Set up authentication callbacks
	if cb := auth.PasswordCallback(); cb != nil {
		s.sshCfg.PasswordCallback = cb
	}
	if cb := auth.PublicKeyCallback(); cb != nil {
		s.sshCfg.PublicKeyCallback = cb
	}
	if cb := auth.NoClientAuthCallback(); cb != nil {
		s.sshCfg.NoClientAuth = true
		s.sshCfg.NoClientAuthCallback = cb
	}

	return s, nil
}

// loadOrGenerateHostKey loads an existing host key or generates a new one
func (s *Server) loadOrGenerateHostKey(ctx context.Context) (ssh.Signer, error) {
	// Try to load existing key
	keyData, err := os.ReadFile(s.cfg.HostKeyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err == nil {
			log.Ctx(ctx).Info().Str("path", s.cfg.HostKeyPath).Msg("loaded host key")
			return signer, nil
		}
		log.Ctx(ctx).Warn().Err(err).Msg("failed to parse host key, generating new one")
	}

	// Generate new ED25519 key
	log.Ctx(ctx).Info().Msg("generating new ED25519 host key")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: marshalED25519PrivateKey(privateKey),
	}
	keyData = pem.EncodeToMemory(pemBlock)

	// Save to file
	if err := os.WriteFile(s.cfg.HostKeyPath, keyData, 0600); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("failed to save host key")
	} else {
		log.Ctx(ctx).Info().Str("path", s.cfg.HostKeyPath).Msg("saved host key")
	}

	return ssh.NewSignerFromKey(privateKey)
}

// marshalED25519PrivateKey marshals an ED25519 private key to OpenSSH format
func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	// OpenSSH private key format
	pubKey := key.Public().(ed25519.PublicKey)

	// Build the key blob
	var keyBlob []byte

	// Auth magic
	authMagic := []byte("openssh-key-v1\x00")
	keyBlob = append(keyBlob, authMagic...)

	// Cipher name (none)
	keyBlob = appendString(keyBlob, "none")
	// KDF name (none)
	keyBlob = appendString(keyBlob, "none")
	// KDF options (empty)
	keyBlob = appendString(keyBlob, "")

	// Number of keys
	keyBlob = appendUint32(keyBlob, 1)

	// Public key
	pubKeyBlob := marshalED25519PublicKey(pubKey)
	keyBlob = appendBytes(keyBlob, pubKeyBlob)

	// Private key section
	var privSection []byte
	// Check numbers (random, must match)
	checkNum := make([]byte, 4)
	rand.Read(checkNum)
	privSection = append(privSection, checkNum...)
	privSection = append(privSection, checkNum...)

	// Key type
	privSection = appendString(privSection, "ssh-ed25519")
	// Public key
	privSection = appendBytes(privSection, pubKey)
	// Private key (ed25519 private key is seed + public key)
	privSection = appendBytes(privSection, key)
	// Comment
	privSection = appendString(privSection, "sshdev")

	// Padding
	for i := 1; len(privSection)%8 != 0; i++ {
		privSection = append(privSection, byte(i))
	}

	keyBlob = appendBytes(keyBlob, privSection)

	return keyBlob
}

func marshalED25519PublicKey(key ed25519.PublicKey) []byte {
	var blob []byte
	blob = appendString(blob, "ssh-ed25519")
	blob = appendBytes(blob, key)
	return blob
}

func appendString(b []byte, s string) []byte {
	return appendBytes(b, []byte(s))
}

func appendBytes(b []byte, data []byte) []byte {
	b = appendUint32(b, uint32(len(data)))
	return append(b, data...)
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Start starts the SSH server
func (s *Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	ctx := context.Background()
	log.Ctx(ctx).Info().Str("addr", s.cfg.ListenAddr).Msg("SSH server listening")
	if s.cfg.AuthMode == types.AuthModeNone {
		log.Ctx(ctx).Warn().Msg("NO AUTHENTICATION MODE ENABLED - ANYONE CAN CONNECT")
	}

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				log.Ctx(ctx).Error().Err(err).Msg("failed to accept connection")
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	ctx := context.Background()
	log.Ctx(ctx).Info().Str("remote", conn.RemoteAddr().String()).Msg("new connection")

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshCfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("SSH handshake failed")
		return
	}
	defer sshConn.Close()

	newCtx := log.With().
		Str("user", sshConn.User()).
		Str("client", sshConn.RemoteAddr().String()).
		Logger().WithContext(ctx)

	log.Ctx(newCtx).Info().Msg("SSH connection established")

	// Create forward manager for remote port forwarding
	forwardMgr := session.NewForwardManager(sshConn)
	defer forwardMgr.Close()

	// Handle global requests
	go s.handleGlobalRequests(newCtx, reqs, forwardMgr)

	// Handle channels
	for newChannel := range chans {
		s.handleChannel(newCtx, newChannel, sshConn)
	}

	log.Ctx(newCtx).Info().Msg("connection closed")
}

// handleGlobalRequests handles global SSH requests
func (s *Server) handleGlobalRequests(ctx context.Context, reqs <-chan *ssh.Request, forwardMgr *session.ForwardManager) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			// Remote port forwarding request
			if s.cfg.DisableRemoteForward {
				log.Ctx(ctx).Warn().Msg("remote port forwarding not allowed")
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			forwardMgr.HandleTcpipForward(ctx, req)
		case "cancel-tcpip-forward":
			// Cancel remote port forwarding
			forwardMgr.CancelForward(ctx, req)
		case "keepalive@openssh.com":
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			log.Ctx(ctx).Debug().Str("type", req.Type).Msg("unknown global request")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleChannel handles a new SSH channel
func (s *Server) handleChannel(ctx context.Context, newChannel ssh.NewChannel, conn *ssh.ServerConn) {
	channelType := newChannel.ChannelType()

	switch channelType {
	case "session":
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			session.HandleSession(ctx, newChannel, s.cfg)
		}()

	case "direct-tcpip":
		// Local port forwarding
		if s.cfg.DisablePortForward {
			log.Ctx(ctx).Warn().Msg("local port forwarding not allowed")
			newChannel.Reject(ssh.Prohibited, "port forwarding not allowed")
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			session.HandleDirectTcpip(ctx, newChannel)
		}()

	default:
		log.Ctx(ctx).Warn().Str("type", channelType).Msg("rejecting unknown channel type")
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channelType))
	}
}

// Stop stops the SSH server gracefully
func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	ctx := context.Background()
	log.Ctx(ctx).Info().Msg("SSH server stopped")
}