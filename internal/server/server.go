package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/embedded"
	"github.com/117503445/sshdev/internal/auth"
	"github.com/117503445/sshdev/internal/session"
	"github.com/117503445/sshdev/internal/types"
)

// Server represents the SSH server
type Server struct {
	cfg        *types.Config
	sshCfg     *ssh.ServerConfig
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
	connIDGen  atomic.Uint64
}

// NewServer creates a new SSH server
func NewServer(cfg *types.Config) (*Server, error) {
	log.Info().Msg("Creating new SSH server instance")

	s := &Server{
		cfg:  cfg,
		quit: make(chan struct{}),
	}

	// Load or generate host key
	log.Info().Msg("Loading or generating host key")
	hostKey, err := s.loadOrGenerateHostKey(context.Background())
	if err != nil {
		log.Error().Err(err).Msg("Failed to load or generate host key")
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}
	log.Info().Msg("Host key loaded successfully")

	// Create authenticator
	log.Info().Msg("Creating authenticator")
	auth, err := auth.NewAuthenticator(cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create authenticator")
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}
	log.Info().Msg("Authenticator created")

	// Create SSH server config
	s.sshCfg = &ssh.ServerConfig{}
	s.sshCfg.AddHostKey(hostKey)

	// Set up authentication callbacks
	if cb := auth.PasswordCallback(); cb != nil {
		s.sshCfg.PasswordCallback = cb
		log.Info().Msg("Password authentication enabled")
	}
	if cb := auth.PublicKeyCallback(); cb != nil {
		s.sshCfg.PublicKeyCallback = cb
		log.Info().Msg("Public key authentication enabled")
	}
	if cb := auth.NoClientAuthCallback(); cb != nil {
		s.sshCfg.NoClientAuth = true
		s.sshCfg.NoClientAuthCallback = cb
		log.Info().Msg("No client authentication enabled (insecure)")
	}

	log.Info().Msg("SSH server instance created successfully")
	return s, nil
}

// loadOrGenerateHostKey loads an existing host key or generates a new one
func (s *Server) loadOrGenerateHostKey(ctx context.Context) (ssh.Signer, error) {
	// Priority: HostKeyContent (env) > HostKeyBuiltin (env) > HostKeyPath (file) > generate random

	// 1. Try HostKeyContent (direct key content from env)
	if s.cfg.HostKeyContent != "" {
		signer, err := ssh.ParsePrivateKey([]byte(s.cfg.HostKeyContent))
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSHDEV_HOST_KEY: %w", err)
		}
		log.Ctx(ctx).Info().Msg("loaded host key from SSHDEV_HOST_KEY")
		return signer, nil
	}

	// 2. Try HostKeyBuiltin (built-in embedded key)
	if s.cfg.HostKeyBuiltin {
		signer, err := ssh.ParsePrivateKey([]byte(embedded.HostKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse built-in host key: %w", err)
		}
		log.Ctx(ctx).Info().Msg("loaded built-in host key (SSHDEV_HOST_KEY_BUILTIN)")
		return signer, nil
	}

	// 3. Try HostKeyPath (file path)
	if s.cfg.HostKeyPath != "" {
		keyData, err := os.ReadFile(s.cfg.HostKeyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyData)
			if err == nil {
				log.Ctx(ctx).Info().Str("path", s.cfg.HostKeyPath).Msg("loaded host key from file")
				return signer, nil
			}
			log.Ctx(ctx).Warn().Err(err).Msg("failed to parse host key file, generating new one")
		}
	}

	// 4. Generate new ED25519 key (don't save to file)
	log.Ctx(ctx).Info().Msg("generating new random ED25519 host key")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(privateKey)
}

// Start starts the SSH server
func (s *Server) Start(ctx context.Context) error {
	log.Info().Str("addr", s.cfg.ListenAddr).Msg("Starting to listen on TCP address")

	var err error
	s.listener, err = net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		log.Error().Err(err).Str("addr", s.cfg.ListenAddr).Msg("Failed to listen on TCP address")
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Info().Str("addr", s.cfg.ListenAddr).Msg("SSH server listening")
	if !s.cfg.HasPasswordAuth() && !s.cfg.HasPublicKeyAuth() {
		log.Warn().Msg("NO AUTHENTICATION MODE ENABLED - ANYONE CAN CONNECT")
	}

	log.Info().Msg("Entering main accept loop")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				log.Info().Msg("Accept loop exiting due to quit signal")
				return nil
			default:
				log.Error().Err(err).Msg("failed to accept connection")
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

// handleConnection handles a single SSH connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	// Assign a unique connection ID
	connID := s.connIDGen.Add(1)
	ctx = log.With().Uint64("connID", connID).Logger().WithContext(ctx)

	defer func() {
		s.wg.Done()
		conn.Close()
		log.Ctx(ctx).Info().Msg("connection closed")
	}()

	log.Ctx(ctx).Info().Str("remote", conn.RemoteAddr().String()).Msg("new connection")

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshCfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("SSH handshake failed")
		return
	}
	defer sshConn.Close()

	newCtx := log.Ctx(ctx).With().
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