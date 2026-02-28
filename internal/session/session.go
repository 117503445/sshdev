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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/internal/types"
	"github.com/117503445/sshdev/internal/utils"
)

func init() {
	// Set log level to debug for testing
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
}

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
	log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: starting")

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to accept session channel")
		return
	}
	log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: channel accepted")

	defer func() {
		log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: closing channel (defer)")
		channel.Close()
		log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: channel closed (defer)")
	}()

	state := &sessionState{
		env:   os.Environ(),
		winCh: make(chan windowChangeMsg, 1),
	}

	log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: entering request loop")

	// Handle requests
	for req := range requests {
		log.Ctx(ctx).Info().
			Str("type", req.Type).
			Bool("want_reply", req.WantReply).
			Msg("[DEBUG] HandleSession: received request")

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

		log.Ctx(ctx).Info().
			Bool("shouldExit", shouldExit).
			Msg("[DEBUG] HandleSession: request processed")

		// Exit the loop after shell/exec/subsystem completes
		if shouldExit {
			log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: breaking loop (shouldExit=true)")
			break
		}
	}

	log.Ctx(ctx).Info().Msg("[DEBUG] HandleSession: exited request loop, returning")
}

// handlePtyReq handles a pty request
func handlePtyReq(ctx context.Context, req *ssh.Request, state *sessionState, cfg *types.Config) {
	log.Ctx(ctx).Info().Msg("[DEBUG] handlePtyReq: starting")

	var msg ptyReqMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse pty-req")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Info().
		Str("term", msg.Term).
		Int("cols", int(msg.Columns)).
		Int("rows", int(msg.Rows)).
		Msg("[DEBUG] handlePtyReq: pty request parsed")

	req.Reply(true, nil)
	log.Ctx(ctx).Info().Msg("[DEBUG] handlePtyReq: replied true")
}

// handleX11Req handles an X11 forwarding request
func handleX11Req(ctx context.Context, req *ssh.Request) {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleX11Req: starting")
	req.Reply(true, nil)
}

// handleEnvReq handles an environment request
func handleEnvReq(ctx context.Context, req *ssh.Request, state *sessionState) {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleEnvReq: starting")

	var msg struct {
		Name  string
		Value string
	}
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse env")
		req.Reply(false, nil)
		return
	}

	log.Ctx(ctx).Info().Str("name", msg.Name).Str("value", msg.Value).Msg("[DEBUG] handleEnvReq: env parsed")

	envVar := fmt.Sprintf("%s=%s", msg.Name, msg.Value)
	state.mu.Lock()
	state.env = append(state.env, envVar)
	state.mu.Unlock()

	req.Reply(true, nil)
}

// handleShellReq handles a shell request
func handleShellReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: starting")

	state.mu.Lock()
	log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: mutex locked")

	if state.pty != nil {
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: using existing PTY")
		ptmx := state.pty
		state.mu.Unlock()
		req.Reply(true, nil)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: starting io.Copy channel <- ptmx")
			io.Copy(channel, ptmx)
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: io.Copy channel <- ptmx done")
		}()

		go func() {
			defer wg.Done()
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: starting io.Copy ptmx <- channel")
			io.Copy(ptmx, channel)
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: io.Copy ptmx <- channel done")
		}()

		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: waiting for copy operations")
		wg.Wait()
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: copy operations done")

		ptmx.Close()
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: ptmx closed")
	} else {
		log.Ctx(ctx).Info().Str("shell", cfg.Shell).Msg("[DEBUG] handleShellReq: starting new PTY")

		cmd := exec.Command(cfg.Shell)
		cmd.Env = state.env

		ptmx, err := pty.Start(cmd)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("failed to start shell with PTY")
			req.Reply(false, nil)
			state.mu.Unlock()
			return true
		}
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: PTY started")

		state.mu.Unlock()
		req.Reply(true, nil)
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: replied true")

		// Use a done channel to signal when one direction finishes
		done := make(chan struct{}, 2)

		// Copy from PTY to channel (read shell output)
		go func() {
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: starting io.Copy channel <- ptmx (read from PTY)")
			n, err := io.Copy(channel, ptmx)
			log.Ctx(ctx).Info().
				Int64("bytes", n).
				Err(err).
				Msg("[DEBUG] handleShellReq: io.Copy channel <- ptmx done")
			done <- struct{}{}
		}()

		// Copy from channel to PTY (write user input)
		go func() {
			log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: starting io.Copy ptmx <- channel (write to PTY)")
			n, err := io.Copy(ptmx, channel)
			log.Ctx(ctx).Info().
				Int64("bytes", n).
				Err(err).
				Msg("[DEBUG] handleShellReq: io.Copy ptmx <- channel done")
			done <- struct{}{}
		}()

		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: waiting for first copy operation to finish")

		// Wait for the first copy operation to finish (usually PTY output ends when shell exits)
		<-done
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: first copy operation done, closing both ptmx and channel")

		// Close ptmx to unblock the other copy operation
		ptmx.Close()

		// Close channel to stop the other io.Copy and notify client
		channel.Close()

		// Wait for the second copy operation to finish
		<-done
		log.Ctx(ctx).Info().Msg("[DEBUG] handleShellReq: both copy operations done")

		// Wait for shell process to complete
		err = cmd.Wait()
		log.Ctx(ctx).Info().Err(err).Msg("[DEBUG] handleShellReq: cmd.Wait() returned")

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

		log.Ctx(ctx).Info().Uint32("exit_status", exitStatus).Msg("[DEBUG] handleShellReq: shell completed (exit-status not sent because channel already closed)")
	}

	return true
}

// handleExecReq handles an exec request
func handleExecReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleExecReq: starting")

	var msg execMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse exec")
		req.Reply(false, nil)
		return true
	}

	log.Ctx(ctx).Info().Str("command", msg.Command).Msg("[DEBUG] handleExecReq: command parsed")

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
	log.Ctx(ctx).Info().Uint32("exit_status", exitStatus).Msg("[DEBUG] handleExecReq: exec completed")

	return true
}

// handleSubsystemReq handles a subsystem request
func handleSubsystemReq(ctx context.Context, req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *types.Config) bool {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleSubsystemReq: starting")

	var msg subsystemMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to parse subsystem")
		req.Reply(false, nil)
		return true
	}

	log.Ctx(ctx).Info().Str("subsystem", msg.Subsystem).Msg("[DEBUG] handleSubsystemReq: subsystem parsed")

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
	log.Ctx(ctx).Info().Msg("[DEBUG] handleWindowChangeReq: starting")

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

	log.Ctx(ctx).Info().Int("cols", int(msg.Cols)).Int("rows", int(msg.Rows)).Msg("[DEBUG] handleWindowChangeReq: parsed")

	select {
	case state.winCh <- windowChangeMsg{cols: msg.Cols, rows: msg.Rows}:
	default:
	}

	req.Reply(true, nil)
}

// handleSignalReq handles a signal request
func handleSignalReq(ctx context.Context, req *ssh.Request) {
	log.Ctx(ctx).Info().Msg("[DEBUG] handleSignalReq: starting")

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
		log.Ctx(ctx).Info().Str("signal", sigName).Msg("[DEBUG] handleSignalReq: valid signal")
		req.Reply(true, nil)
	} else {
		log.Ctx(ctx).Warn().Str("signal", sigName).Msg("unknown signal")
		req.Reply(false, nil)
	}
}

// sendExitStatus sends the exit status to the SSH channel
func sendExitStatus(channel ssh.Channel, state *sessionState) {
	var exitStatus uint32 = 0

	exitStatusData := []byte{0, 0, 0, 0}
	exitStatusData[0] = byte(exitStatus >> 24)
	exitStatusData[1] = byte(exitStatus >> 16)
	exitStatusData[2] = byte(exitStatus >> 8)
	exitStatusData[3] = byte(exitStatus)

	payload := append([]byte{0, 0, 0, 11}, []byte("exit-status")...)
	payload = append(payload, exitStatusData...)

	log.Debug().Uint32("exit_status", exitStatus).Msg("sending exit status")
}

// HandleDirectTcpip handles direct TCP/IP forwarding
func HandleDirectTcpip(ctx context.Context, newChannel ssh.NewChannel) {
	log.Ctx(ctx).Info().Msg("[DEBUG] HandleDirectTcpip: starting")

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
		Msg("[DEBUG] HandleDirectTcpip: parsed")

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

	log.Ctx(ctx).Info().Str("dest", destAddr).Msg("[DEBUG] HandleDirectTcpip: closed")
}