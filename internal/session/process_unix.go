//go:build !windows

package session

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// shellArgs 根据 shell、command 和 isExec 返回 Unix shell 参数。
func shellArgs(shell, command string, isExec bool) []string {
	if isExec {
		return []string{"-c", command}
	}
	return nil
}

// prepareCommand 为 cmd 建立独立进程组，便于断线时回收子进程。
func prepareCommand(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// manageProcess 返回 pid 所在进程组的清理函数。
func manageProcess(pid int) (func(), error) {
	return func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }, nil
}

// signalProcess 将 name 对应的 SSH 信号发送给 pid 所在的进程组。
func signalProcess(pid int, name string) error {
	signals := map[string]syscall.Signal{"INT": syscall.SIGINT, "TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL, "HUP": syscall.SIGHUP, "QUIT": syscall.SIGQUIT, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2}
	sig, ok := signals[strings.TrimPrefix(strings.ToUpper(name), "SIG")]
	if !ok {
		return unsupportedSignal(name)
	}
	return syscall.Kill(-pid, sig)
}

// exitResult 将 err 转为 SSH 退出码及信号名称。
func exitResult(err error) (uint32, string) {
	if err == nil {
		return 0, ""
	}
	var e *exec.ExitError
	if errors.As(err, &e) {
		if status, ok := e.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			names := map[syscall.Signal]string{syscall.SIGINT: "INT", syscall.SIGTERM: "TERM", syscall.SIGKILL: "KILL", syscall.SIGHUP: "HUP", syscall.SIGQUIT: "QUIT", syscall.SIGPIPE: "PIPE"}
			return uint32(128 + status.Signal()), names[status.Signal()]
		}
		return uint32(e.ExitCode()), ""
	}
	return 1, ""
}

// startTerminal 为 cmd 建立 term 指定的 Unix PTY，并将输入输出接到 ch。
func startTerminal(ch ssh.Channel, cmd *exec.Cmd, term *terminalRequest) (*process, error) {
	terminal, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(term.Columns), Rows: uint16(term.Rows)})
	if err != nil {
		return nil, err
	}
	if err = applyTerminalModes(terminal, term.Modes); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
		terminal.Close()
		return nil, err
	}
	drained := copyTerminal(ch, terminal)
	return &process{
		done: make(chan struct{}),
		kill: func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); terminal.Close() },
		signal: func(name string) error {
			group, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
			if err != nil {
				return err
			}
			if group <= 0 {
				return unsupportedSignal(name)
			}
			return signalProcess(group, name)
		},
		resize: func(cols, rows uint32) error {
			return pty.Setsize(terminal, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
		},
		wait: func() (uint32, string) {
			code, sig := exitResult(cmd.Wait())
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			drained()
			return code, sig
		},
	}, nil
}

// resumeCommand 在 Unix 无需额外恢复；pid 为已启动进程。
func resumeCommand(pid int) error { return nil }
