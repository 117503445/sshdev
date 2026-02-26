package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/creack/pty"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/internal/types"
	"github.com/117503445/sshdev/internal/utils"
)

// sessionState holds the state for an SSH session
type sessionState struct {
	mu    sync.Mutex
	env   []string
	pty   *os.File
	winCh chan windowChangeMsg
}

type windowChangeMsg struct {
	cols uint32
	rows uint32
}

type ptyReqMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

type execMsg struct {
	Command string
}

type subsystemMsg struct {
	Subsystem string
}

// HandleSession handles a session channel
func HandleSession(ctx context.Context, newChannel ssh.NewChannel, cfg *types.Config) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to accept session channel")
		return
	}
	defer channel.Close()

	state := &sessionState{
		env:   os.Environ(),
		winCh: make(chan windowChangeMsg, 1),
	}

	// Handle requests
	for req := range requests {
		ctxWithReq := log.Ctx(ctx).With().
			Str("request_type", req.Type).
			Bool("want_reply", req.WantReply).
			Logger().WithContext(ctx)

		switch req.Type {
		case "pty-req":
			handlePtyReq(ctxWithReq, req, state, cfg)
		case "x11-req":
			handleX11Req(ctxWithReq, req)
		case "env":
			handleEnvReq(ctxWithReq, req, state)
		case "shell":
			handleShellReq(ctxWithReq, req, channel, state, cfg)
		case "exec":
			handleExecReq(ctxWithReq, req, channel, state, cfg)
		case "subsystem":
			handleSubsystemReq(ctxWithReq, req, channel, state, cfg)
		case "window-change":
			handleWindowChangeReq(ctxWithReq, req, state)
		case "signal":
			handleSignalReq(ctxWithReq, req)
		default:
			log.Ctx(ctx).Debug().Str("type", req.Type).Msg("unknown session request")
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handlePtyReq handles a pty request
func handlePtyReq(ctx context.Context, req *ssh.Request, state *sessionState, cfg *types.Config) {
	var msg ptyReqMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse pty-req")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Debug().
		Str("term", msg.Term).
		Int("cols", int(msg.Columns)).
		Int("rows", int(msg.Rows)).
		Msg("pty request")

	// Store pty request info in session state
	// The actual pty will be set up when shell/exec is requested
	req.Reply(true, nil)
}

// handleX11Req handles an X11 forwarding request
func handleX11Req(ctx context.Context, req *ssh.Request) {
	log.Ctx(ctx).Debug().Msg("x11 request")
	req.Reply(true, nil)
}

// handleEnvReq handles an environment request
func handleEnvReq(ctx context.Context, req *ssh.Request, state *sessionState) {
	var msg struct {
		Name  string
		Value string
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse env")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Debug().Str("name", msg.Name).Str("value", msg.Value).Msg("env set")

	// Add to environment
	envVar := fmt.Sprintf("%s=%s", msg.Name, msg.Value)
	state.mu.Lock()
	state.env = append(state.env, envVar)
	state.mu.Unlock()

	req.Reply(true, nil)
}

// handleShellReq handles a shell request
func handleShellReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) {
	log.Ctx(ctx).Debug().Msg("shell request")

	state.mu.Lock()

	if state.pty != nil {
		// Use existing PTY if available
		ptmx := state.pty
		go func() {
			io.Copy(channel, ptmx)
			ptmx.Close()
		}()

		go func() {
			io.Copy(ptmx, channel)
			ptmx.Close()
		}()
	} else {
		// Start shell with new PTY
		cmd := exec.Command(cfg.Shell)
		cmd.Env = state.env

		ptmx, err := pty.Start(cmd)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to start shell with PTY")
			req.Reply(false, nil)
			state.mu.Unlock()
			return
		}

		go func() {
			io.Copy(channel, ptmx)
			ptmx.Close()
		}()

		go func() {
			io.Copy(ptmx, channel)
			ptmx.Close()
		}()
	}

	state.mu.Unlock()
	req.Reply(true, nil)
}

// handleExecReq handles an exec request
func handleExecReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) {
	var msg execMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse exec")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Debug().Str("command", msg.Command).Msg("exec request")

	state.mu.Lock()

	// Start command without PTY for exec requests
	cmd := exec.Command(cfg.Shell, "-c", msg.Command)
	cmd.Env = state.env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdout pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stderr pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdin pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return
	}

	if err := cmd.Start(); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to start command")
		req.Reply(false, nil)
		state.mu.Unlock()
		return
	}

	state.mu.Unlock()
	req.Reply(true, nil)

	// Use sync.WaitGroup to wait for all copy operations
	var wg sync.WaitGroup

	// Copy stdin from channel to command
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(stdinPipe, channel)
		stdinPipe.Close()
	}()

	// Copy stdout to channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stdoutPipe)
	}()

	// Copy stderr to channel (as extended data)
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stderrPipe)
	}()

	// Wait for copy operations to complete
	wg.Wait()

	// Wait for command to complete
	err = cmd.Wait()

	// Send exit status
	var exitStatus uint32
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitStatus = uint32(exitErr.ExitCode())
		} else {
			exitStatus = 1
		}
	} else {
		exitStatus = 0
	}

	// Send exit-status request to channel
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct {
		ExitStatus uint32
	}{exitStatus}))

	channel.Close()
	log.Ctx(ctx).Debug().Uint32("exit_status", exitStatus).Msg("exec completed")
}

// handleSubsystemReq handles a subsystem request
func handleSubsystemReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) {
	var msg subsystemMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse subsystem")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Debug().Str("subsystem", msg.Subsystem).Msg("subsystem request")

	// For now, just handle sftp as an example
	if msg.Subsystem == "sftp" {
		// Placeholder for SFTP subsystem
		log.Ctx(ctx).Info().Str("subsystem", msg.Subsystem).Msg("handling sftp subsystem")
		req.Reply(true, nil)
	} else {
		log.Ctx(ctx).Warn().Str("subsystem", msg.Subsystem).Msg("unsupported subsystem")
		req.Reply(false, nil)
	}
}

// handleWindowChangeReq handles a window change request
func handleWindowChangeReq(ctx context.Context, req *ssh.Request, state *sessionState) {
	var msg struct {
		Cols   uint32
		Rows   uint32
		Width  uint32
		Height uint32
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse window-change")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Debug().Int("cols", int(msg.Cols)).Int("rows", int(msg.Rows)).Msg("window change")

	// Send to PTY resize routine
	select {
	case state.winCh <- windowChangeMsg{cols: msg.Cols, rows: msg.Rows}:
	default:
		// Channel is full, drop the message
	}

	req.Reply(true, nil)
}

// handleSignalReq handles a signal request
func handleSignalReq(ctx context.Context, req *ssh.Request) {
	var msg struct {
		Signal string
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse signal")
		req.Reply(false, nil)
		return
	}

	// Convert SSH signal to OS signal
	sigName := strings.ToUpper(msg.Signal)
	sig := utils.GetSignalByName(sigName)
	if utils.IsValidSignal(sig) {
		log.Ctx(ctx).Debug().Str("signal", sigName).Msg("signal request")
		// We can't really send the signal without a PID, so we just acknowledge
		req.Reply(true, nil)
	} else {
		log.Ctx(ctx).Warn().Str("signal", sigName).Msg("unknown signal")
		req.Reply(false, nil)
	}
}

// sendExitStatus sends the exit status to the SSH channel
func sendExitStatus(channel ssh.Channel, state *sessionState) {
	// Get exit status
	var exitStatus uint32 = 0 // Default to 0

	// Extended data for stderr (optional)
	exitStatusData := []byte{0, 0, 0, 0} // 4-byte exit status in big-endian
	exitStatusData[0] = byte(exitStatus >> 24)
	exitStatusData[1] = byte(exitStatus >> 16)
	exitStatusData[2] = byte(exitStatus >> 8)
	exitStatusData[3] = byte(exitStatus)

	// Send exit-status request
	payload := append([]byte{0, 0, 0, 11}, []byte("exit-status")...) // Request type
	payload = append(payload, exitStatusData...)                      // Exit status

	// We can't send extended requests with the current implementation
	// So we just log it
	log.Debug().Uint32("exit_status", exitStatus).Msg("sending exit status")
}

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

	destAddr := fmt.Sprintf("%s:%d", msg.DestAddr, msg.DestPort)
	log.Ctx(ctx).Info().
		Str("dest_addr", msg.DestAddr).
		Uint32("dest_port", msg.DestPort).
		Str("src_addr", msg.SrcAddr).
		Uint32("src_port", msg.SrcPort).
		Str("full_dest", destAddr).
		Msg("direct-tcpip request")

	// Connect to destination
	conn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("dest", destAddr).Msg("failed to connect")
		newChannel.Reject(ssh.ConnectionFailed, "connect error")
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		conn.Close()
		log.Ctx(ctx).Error().Err(err).Msg("failed to accept direct-tcpip channel")
		return
	}

	// Handle requests on the channel
	go ssh.DiscardRequests(requests)

	// Copy data between connections - when either direction completes, close both
	done := make(chan struct{}, 2)

	// Remote to local (destination -> channel)
	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
		done <- struct{}{}
	}()

	// Local to remote (channel -> destination)
	go func() {
		io.Copy(conn, channel)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- struct{}{}
	}()

	// Wait for both directions to complete
	<-done
	<-done

	// Close both connections
	channel.Close()
	conn.Close()

	log.Ctx(ctx).Debug().Str("dest", destAddr).Msg("direct-tcpip closed")
}
