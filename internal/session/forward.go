package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// ForwardManager manages remote port forwarding
type ForwardManager struct {
	mu        sync.RWMutex
	listeners map[string]net.Listener
	conn      *ssh.ServerConn
	quit      chan struct{}
}

// NewForwardManager creates a new forward manager
func NewForwardManager(conn *ssh.ServerConn) *ForwardManager {
	return &ForwardManager{
		listeners: make(map[string]net.Listener),
		conn:      conn,
		quit:      make(chan struct{}),
	}
}

// HandleTcpipForward handles a tcpip-forward request
func (fm *ForwardManager) HandleTcpipForward(ctx context.Context, req *ssh.Request) {
	var msg struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse tcpip-forward")
		req.Reply(false, nil)
		return
	}

	bindAddr := fmt.Sprintf("%s:%d", msg.BindAddr, msg.BindPort)
	log.Ctx(ctx).Info().Str("addr", bindAddr).Msg("remote port forward request")

	// Start listening
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("addr", bindAddr).Msg("failed to listen")
		req.Reply(false, nil)
		return
	}

	// Get the actual bound port (important for port 0)
	addr := listener.Addr().(*net.TCPAddr)
	boundPort := uint32(addr.Port)

	// Store the listener
	fm.mu.Lock()
	fm.listeners[bindAddr] = listener
	fm.mu.Unlock()

	// Reply with the bound port
	reply := struct {
		Port uint32
	}{boundPort}

	log.Ctx(ctx).Info().Str("addr", bindAddr).Uint32("port", boundPort).Msg("remote port forward active")
	req.Reply(true, ssh.Marshal(reply))

	// Start accepting connections
	go fm.acceptForwardedConnections(ctx, listener, msg.BindAddr, boundPort)
}

// acceptForwardedConnections accepts connections and forwards them to the SSH client
func (fm *ForwardManager) acceptForwardedConnections(ctx context.Context, listener net.Listener, bindAddr string, bindPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-fm.quit:
				return
			default:
				log.Ctx(ctx).Error().Err(err).Msg("failed to accept forwarded connection")
				return
			}
		}

		go fm.handleForwardedConnection(ctx, conn, bindAddr, bindPort)
	}
}

// handleForwardedConnection handles a single forwarded connection
func (fm *ForwardManager) handleForwardedConnection(ctx context.Context, conn net.Conn, bindAddr string, bindPort uint32) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	// Create "forwarded-tcpip" channel to the SSH client
	payload := struct {
		BindAddr   string
		BindPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		BindAddr:   bindAddr,
		BindPort:   bindPort,
		OriginAddr: remoteAddr.IP.String(),
		OriginPort: uint32(remoteAddr.Port),
	}

	channel, requests, err := fm.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(payload))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to open forwarded-tcpip channel")
		return
	}
	defer channel.Close()

	// Discard requests on this channel
	go ssh.DiscardRequests(requests)

	// Copy data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(channel, conn)
		channel.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, channel)
	}()

	wg.Wait()
}

// CancelForward cancels a remote port forward
func (fm *ForwardManager) CancelForward(ctx context.Context, req *ssh.Request) {
	var msg struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse cancel-tcpip-forward")
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	bindAddr := fmt.Sprintf("%s:%d", msg.BindAddr, msg.BindPort)
	log.Ctx(ctx).Info().Str("addr", bindAddr).Msg("cancel remote port forward")

	fm.mu.Lock()
	if listener, ok := fm.listeners[bindAddr]; ok {
		listener.Close()
		delete(fm.listeners, bindAddr)
	}
	fm.mu.Unlock()

	if req.WantReply {
		req.Reply(true, nil)
	}
}

// Close closes all listeners
func (fm *ForwardManager) Close() {
	close(fm.quit)

	fm.mu.Lock()
	defer fm.mu.Unlock()

	for _, listener := range fm.listeners {
		listener.Close()
	}
	fm.listeners = nil
}