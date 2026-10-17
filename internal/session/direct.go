package session

import (
	"context"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strconv"
	"time"
)

// HandleDirectTcpip handles direct TCP/IP forwarding
func HandleDirectTcpip(ctx context.Context, newChannel ssh.NewChannel) {
	var msg struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse direct-tcpip")
		newChannel.Reject(ssh.ConnectionFailed, "parse error")
		return
	}

	destAddr := net.JoinHostPort(msg.DestAddr, strconv.Itoa(int(msg.DestPort)))

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("dest", destAddr).Msg("failed to connect")
		newChannel.Reject(ssh.ConnectionFailed, "connect error")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		conn.Close()
		log.Ctx(ctx).Error().Err(err).Msg("failed to accept direct-tcpip channel")
		return
	}

	go ssh.DiscardRequests(requests)
	stop := context.AfterFunc(ctx, func() { channel.Close(); conn.Close() })
	defer stop()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn, channel)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done

	channel.Close()
	conn.Close()
}
