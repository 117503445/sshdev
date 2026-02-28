package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
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

		var shouldExit bool

		switch req.Type {
		case "pty-req":
			handlePtyReq(ctxWithReq, req, state, cfg)
		case "x11-req":
			handleX11Req(ctxWithReq, req)
		case "env":
			handleEnvReq(ctxWithReq, req, state)
		case "shell":
			shouldExit = handleShellReq(ctxWithReq, req, channel, state, cfg)
		case "exec":
			shouldExit = handleExecReq(ctxWithReq, req, channel, state, cfg)
		case "subsystem":
			shouldExit = handleSubsystemReq(ctxWithReq, req, channel, state, cfg)
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

		// Exit the loop after shell/exec/subsystem completes
		if shouldExit {
			break
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

	req.Reply(true, nil)
}

// handleX11Req handles an X11 forwarding request
func handleX11Req(ctx context.Context, req *ssh.Request) {
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

	envVar := fmt.Sprintf("%s=%s", msg.Name, msg.Value)
	state.mu.Lock()
	state.env = append(state.env, envVar)
	state.mu.Unlock()

	req.Reply(true, nil)
}

// handleShellReq handles a shell request
func handleShellReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	state.mu.Lock()

	if state.pty != nil {
		ptmx := state.pty
		state.mu.Unlock()
		req.Reply(true, nil)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(channel, ptmx)
		}()

		go func() {
			defer wg.Done()
			io.Copy(ptmx, channel)
		}()

		wg.Wait()
		ptmx.Close()
	} else {
		cmd := exec.Command(cfg.Shell)
		cmd.Env = state.env

		// Try PTY first (Unix-like systems)
		ptmx, err := pty.Start(cmd)
		if err != nil {
			// PTY not supported (e.g., Windows) - use direct pipes
			if err == pty.ErrUnsupported {
				log.Ctx(ctx).Info().Msg("PTY not supported on this platform, using direct pipes")
				state.mu.Unlock()
				return runShellWithPipes(ctx, req, channel, cmd)
			}
			log.Ctx(ctx).Error().Err(err).Msg("failed to start shell with PTY")
			req.Reply(false, nil)
			state.mu.Unlock()
			return true
		}

		state.mu.Unlock()
		req.Reply(true, nil)

		// Use a done channel to signal when one direction finishes
		done := make(chan struct{}, 2)

		// Copy from PTY to channel (read shell output)
		go func() {
			io.Copy(channel, ptmx)
			done <- struct{}{}
		}()

		// Copy from channel to PTY (write user input)
		go func() {
			io.Copy(ptmx, channel)
			done <- struct{}{}
		}()

		// Wait for the first copy operation to finish (usually PTY output ends when shell exits)
		<-done

		// Close ptmx to unblock the other copy operation
		ptmx.Close()

		// Close channel to stop the other io.Copy and notify client
		channel.Close()

		// Wait for the second copy operation to finish
		<-done

		// Wait for shell process to complete
		cmd.Wait()
	}

	return true
}

// runShellWithPipes runs a shell using direct stdin/stdout/stderr pipes (for Windows)
func runShellWithPipes(ctx context.Context, req *ssh.Request, channel ssh.Channel, cmd *exec.Cmd) bool {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdin pipe")
		req.Reply(false, nil)
		return true
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdout pipe")
		req.Reply(false, nil)
		return true
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stderr pipe")
		req.Reply(false, nil)
		return true
	}

	if err := cmd.Start(); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to start shell")
		req.Reply(false, nil)
		return true
	}

	req.Reply(true, nil)
	log.Ctx(ctx).Info().Msg("Shell started successfully with pipes")

	var wg sync.WaitGroup

	// Copy from channel to stdin (write user input)
	// On Windows, convert \r to \r\n for proper line endings
	wg.Add(1)
	go func() {
		defer wg.Done()
		if runtime.GOOS == "windows" {
			copyWithCRTranslation(stdinPipe, channel)
		} else {
			io.Copy(stdinPipe, channel)
		}
		stdinPipe.Close()
	}()

	// Copy from stdout to channel (read shell output)
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stdoutPipe)
	}()

	// Copy from stderr to channel (read shell errors)
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stderrPipe)
	}()

	wg.Wait()

	// Wait for the shell to complete
	err = cmd.Wait()
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("shell exited with error")
	}

	log.Ctx(ctx).Info().Msg("Shell process completed")
	return true
}

// copyWithCRTranslation copies from src to dst, translating \r to \r\n
// This is needed for Windows shells that expect \r\n line endings
func copyWithCRTranslation(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Replace \r with \r\n (but not \r\n -> \r\r\n)
			data := buf[:n]
			// First replace \r\n with a placeholder to avoid double conversion
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\x00N\x00"))
			// Then replace standalone \r with \r\n
			data = bytes.ReplaceAll(data, []byte("\r"), []byte("\r\n"))
			// Restore the original \r\n
			data = bytes.ReplaceAll(data, []byte("\x00N\x00"), []byte("\r\n"))

			if _, writeErr := dst.Write(data); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// handleExecReq handles an exec request
func handleExecReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	var msg execMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse exec")
		req.Reply(false, nil)
		return true
	}

	state.mu.Lock()

	cmd := exec.Command(cfg.Shell, "-c", msg.Command)
	cmd.Env = state.env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdout pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return true
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stderr pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return true
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to create stdin pipe")
		req.Reply(false, nil)
		state.mu.Unlock()
		return true
	}

	if err := cmd.Start(); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to start command")
		req.Reply(false, nil)
		state.mu.Unlock()
		return true
	}

	state.mu.Unlock()
	req.Reply(true, nil)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(stdinPipe, channel)
		stdinPipe.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stdoutPipe)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(channel, stderrPipe)
	}()

	wg.Wait()

	err = cmd.Wait()

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

	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct {
		ExitStatus uint32
	}{exitStatus}))

	channel.Close()

	return true
}

// handleSubsystemReq handles a subsystem request
func handleSubsystemReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	var msg subsystemMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse subsystem")
		req.Reply(false, nil)
		return true
	}

	if msg.Subsystem == "sftp" {
		log.Ctx(ctx).Info().Str("subsystem", msg.Subsystem).Msg("handling sftp subsystem")
		req.Reply(true, nil)
	} else {
		log.Ctx(ctx).Warn().Str("subsystem", msg.Subsystem).Msg("unsupported subsystem")
		req.Reply(false, nil)
	}

	return true
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

	select {
	case state.winCh <- windowChangeMsg{cols: msg.Cols, rows: msg.Rows}:
	default:
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

	sigName := strings.ToUpper(msg.Signal)
	sig := utils.GetSignalByName(sigName)
	if utils.IsValidSignal(sig) {
		req.Reply(true, nil)
	} else {
		log.Ctx(ctx).Warn().Str("signal", sigName).Msg("unknown signal")
		req.Reply(false, nil)
	}
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

	conn, err := net.Dial("tcp", destAddr)
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