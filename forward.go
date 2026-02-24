package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// directTcpipMsg represents a direct-tcpip channel request
type directTcpipMsg struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// tcpipForwardMsg represents a tcpip-forward request
type tcpipForwardMsg struct {
	BindAddr string
	BindPort uint32
}

// tcpipForwardReply represents a tcpip-forward reply
type tcpipForwardReply struct {
	BoundPort uint32
}

// handleDirectTcpip handles a direct-tcpip channel (local port forwarding)
func handleDirectTcpip(ctx context.Context, newChannel ssh.NewChannel) {
	var msg directTcpipMsg
	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse direct-tcpip")
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse direct-tcpip")
		return
	}

	destAddr := net.JoinHostPort(msg.DestAddr, itoa(msg.DestPort))
	log.Ctx(ctx).Info().
		Str("origin", msg.OriginAddr).
		Int("origin_port", int(msg.OriginPort)).
		Str("dest", destAddr).
		Msg("direct-tcpip")

	// Connect to destination
	conn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("dest", destAddr).Msg("failed to connect")
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to accept direct-tcpip channel")
		conn.Close()
		return
	}

	// Discard requests
	go ssh.DiscardRequests(requests)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, channel)
		// Close write side
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(channel, conn)
		channel.CloseWrite()
	}()

	wg.Wait()
	conn.Close()
	channel.Close()

	log.Ctx(ctx).Debug().Str("dest", destAddr).Msg("direct-tcpip closed")
}

// Remote port forwarding support
var (
	remoteForwards     = make(map[string]net.Listener)
	remoteForwardsLock sync.Mutex
)

// handleTcpipForwardRequest handles a tcpip-forward global request (remote port forwarding)
func handleTcpipForwardRequest(ctx context.Context, req *ssh.Request) {
	var msg tcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse tcpip-forward")
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	bindAddr := net.JoinHostPort(msg.BindAddr, itoa(msg.BindPort))
	log.Ctx(ctx).Info().Str("addr", bindAddr).Msg("remote port forward request")

	// Start listening
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("addr", bindAddr).Msg("failed to listen")
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	// Get the actual bound port (useful when port was 0)
	boundPort := uint32(listener.Addr().(*net.TCPAddr).Port)

	// Store the listener
	remoteForwardsLock.Lock()
	remoteForwards[bindAddr] = listener
	remoteForwardsLock.Unlock()

	if req.WantReply {
		reply := tcpipForwardReply{BoundPort: boundPort}
		req.Reply(true, ssh.Marshal(&reply))
	}

	log.Ctx(ctx).Info().Str("addr", bindAddr).Int("port", int(boundPort)).Msg("remote port forward active")

	// Note: For full implementation, we would need to accept connections
	// and create forwarded-tcpip channels back to the client.
	// This is a simplified implementation that just sets up the listener.
}

// itoa converts uint32 to string
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[i:])
}

// parseUint32 parses a uint32 from bytes
func parseUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
