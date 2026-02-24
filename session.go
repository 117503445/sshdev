package main

import (
	"encoding/binary"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// sessionState holds the state for an SSH session
type sessionState struct {
	pty     *os.File
	tty     *os.File
	cmd     *exec.Cmd
	env     []string
	ptyReq  *ptyRequestMsg
	winCh   chan windowChangeMsg
	mu      sync.Mutex
}

// ptyRequestMsg represents a pty-req message
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// windowChangeMsg represents a window-change message
type windowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

// execMsg represents an exec message
type execMsg struct {
	Command string
}

// envMsg represents an env message
type envMsg struct {
	Name  string
	Value string
}

// exitStatusMsg represents an exit-status message
type exitStatusMsg struct {
	Status uint32
}

// handleSession handles a session channel
func handleSession(newChannel ssh.NewChannel, cfg *Config) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[ERROR] Failed to accept session channel: %v", err)
		return
	}
	defer channel.Close()

	state := &sessionState{
		env:   os.Environ(),
		winCh: make(chan windowChangeMsg, 1),
	}

	// Handle requests
	for req := range requests {
		switch req.Type {
		case "pty-req":
			handlePtyReq(req, state)
		case "env":
			handleEnvReq(req, state)
		case "shell":
			handleShellReq(req, channel, state, cfg)
		case "exec":
			handleExecReq(req, channel, state, cfg)
		case "window-change":
			handleWindowChange(req, state)
		case "signal":
			handleSignal(req, state)
		default:
			log.Printf("[DEBUG] Unknown session request: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handlePtyReq handles a pty-req request
func handlePtyReq(req *ssh.Request, state *sessionState) {
	var msg ptyRequestMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Printf("[ERROR] Failed to parse pty-req: %v", err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	state.mu.Lock()
	state.ptyReq = &msg
	// Set TERM environment variable
	state.env = append(state.env, "TERM="+msg.Term)
	state.mu.Unlock()

	log.Printf("[DEBUG] PTY request: term=%s cols=%d rows=%d", msg.Term, msg.Columns, msg.Rows)

	if req.WantReply {
		req.Reply(true, nil)
	}
}

// handleEnvReq handles an env request
func handleEnvReq(req *ssh.Request, state *sessionState) {
	var msg envMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Printf("[ERROR] Failed to parse env: %v", err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	state.mu.Lock()
	state.env = append(state.env, msg.Name+"="+msg.Value)
	state.mu.Unlock()

	log.Printf("[DEBUG] Env set: %s=%s", msg.Name, msg.Value)

	if req.WantReply {
		req.Reply(true, nil)
	}
}

// handleShellReq handles a shell request
func handleShellReq(req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *Config) {
	log.Printf("[DEBUG] Shell request")

	state.mu.Lock()
	cmd := exec.Command(cfg.Shell)
	cmd.Env = state.env
	state.cmd = cmd
	ptyReq := state.ptyReq
	state.mu.Unlock()

	if ptyReq != nil {
		// Start with PTY
		ptmx, err := pty.Start(cmd)
		if err != nil {
			log.Printf("[ERROR] Failed to start shell with PTY: %v", err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			return
		}

		state.mu.Lock()
		state.pty = ptmx
		state.mu.Unlock()

		// Set initial window size
		setWinSize(ptmx, ptyReq.Columns, ptyReq.Rows)

		if req.WantReply {
			req.Reply(true, nil)
		}

		// Handle window changes
		go func() {
			for msg := range state.winCh {
				state.mu.Lock()
				if state.pty != nil {
					setWinSize(state.pty, msg.Columns, msg.Rows)
				}
				state.mu.Unlock()
			}
		}()

		// Copy data between channel and PTY
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(ptmx, channel)
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel, ptmx)
		}()

		// Wait for command to finish
		cmd.Wait()
		ptmx.Close()
		wg.Wait()
	} else {
		// Start without PTY
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			log.Printf("[ERROR] Failed to start shell: %v", err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			return
		}

		if req.WantReply {
			req.Reply(true, nil)
		}

		// Copy data
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			io.Copy(stdin, channel)
			stdin.Close()
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel, stdout)
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel.Stderr(), stderr)
		}()

		cmd.Wait()
		wg.Wait()
	}

	// Send exit status and close
	sendExitStatus(channel, state)
	channel.Close()
}

// handleExecReq handles an exec request
func handleExecReq(req *ssh.Request, channel ssh.Channel, state *sessionState, cfg *Config) {
	var msg execMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Printf("[ERROR] Failed to parse exec: %v", err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	log.Printf("[DEBUG] Exec request: %s", msg.Command)

	state.mu.Lock()
	cmd := exec.Command(cfg.Shell, "-c", msg.Command)
	cmd.Env = state.env
	state.cmd = cmd
	ptyReq := state.ptyReq
	state.mu.Unlock()

	if ptyReq != nil {
		// Execute with PTY
		ptmx, err := pty.Start(cmd)
		if err != nil {
			log.Printf("[ERROR] Failed to start command with PTY: %v", err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			return
		}

		state.mu.Lock()
		state.pty = ptmx
		state.mu.Unlock()

		// Set initial window size
		setWinSize(ptmx, ptyReq.Columns, ptyReq.Rows)

		if req.WantReply {
			req.Reply(true, nil)
		}

		// Copy data between channel and PTY
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(ptmx, channel)
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel, ptmx)
		}()

		cmd.Wait()
		ptmx.Close()
		wg.Wait()
	} else {
		// Execute without PTY
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			log.Printf("[ERROR] Failed to start command: %v", err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			return
		}

		if req.WantReply {
			req.Reply(true, nil)
		}

		// Copy data
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			io.Copy(stdin, channel)
			stdin.Close()
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel, stdout)
		}()

		go func() {
			defer wg.Done()
			io.Copy(channel.Stderr(), stderr)
		}()

		cmd.Wait()
		wg.Wait()
	}

	// Send exit status and close
	sendExitStatus(channel, state)
	channel.Close()
}

// handleWindowChange handles a window-change request
func handleWindowChange(req *ssh.Request, state *sessionState) {
	var msg windowChangeMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		log.Printf("[ERROR] Failed to parse window-change: %v", err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	log.Printf("[DEBUG] Window change: cols=%d rows=%d", msg.Columns, msg.Rows)

	state.mu.Lock()
	if state.pty != nil {
		setWinSize(state.pty, msg.Columns, msg.Rows)
	}
	state.mu.Unlock()

	// Also send to channel for goroutine handling
	select {
	case state.winCh <- msg:
	default:
	}

	if req.WantReply {
		req.Reply(true, nil)
	}
}

// handleSignal handles a signal request
func handleSignal(req *ssh.Request, state *sessionState) {
	// Signal name is in the payload
	if len(req.Payload) < 4 {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	sigLen := binary.BigEndian.Uint32(req.Payload[:4])
	if len(req.Payload) < int(4+sigLen) {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	sigName := string(req.Payload[4 : 4+sigLen])
	log.Printf("[DEBUG] Signal request: %s", sigName)

	state.mu.Lock()
	cmd := state.cmd
	state.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		sig := signalFromName(sigName)
		if sig != nil {
			cmd.Process.Signal(sig)
		}
	}

	if req.WantReply {
		req.Reply(true, nil)
	}
}

// signalFromName converts a signal name to syscall.Signal
func signalFromName(name string) os.Signal {
	switch name {
	case "HUP":
		return syscall.SIGHUP
	case "INT":
		return syscall.SIGINT
	case "QUIT":
		return syscall.SIGQUIT
	case "TERM":
		return syscall.SIGTERM
	case "KILL":
		return syscall.SIGKILL
	case "USR1":
		return syscall.SIGUSR1
	case "USR2":
		return syscall.SIGUSR2
	default:
		return nil
	}
}

// setWinSize sets the window size of a PTY
func setWinSize(f *os.File, cols, rows uint32) {
	ws := struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}{
		Row: uint16(rows),
		Col: uint16(cols),
	}
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

// sendExitStatus sends the exit status to the channel
func sendExitStatus(channel ssh.Channel, state *sessionState) {
	state.mu.Lock()
	cmd := state.cmd
	state.mu.Unlock()

	var exitCode uint32
	if cmd != nil && cmd.ProcessState != nil {
		exitCode = uint32(cmd.ProcessState.ExitCode())
	}

	exitMsg := exitStatusMsg{Status: exitCode}
	channel.SendRequest("exit-status", false, ssh.Marshal(&exitMsg))
}
