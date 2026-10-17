//go:build !windows

package session

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

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
	// pty 内部 ioctl 会把文件切回阻塞模式；复制描述符并重新注册到 Go 轮询器。
	fd, err := unix.FcntlInt(terminal.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
		terminal.Close()
		return nil, err
	}
	terminal.Close()
	terminal = os.NewFile(uintptr(fd), "sshdev-pty")
	killGroup := func() {
		group, _ := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		if group > 0 && group != cmd.Process.Pid {
			_ = syscall.Kill(-group, syscall.SIGKILL)
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	drained := copyTerminal(ch, terminal)
	p := &process{
		done: make(chan struct{}),
		kill: func() { killGroup(); terminal.Close() },
		signal: func(name string) error {
			group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
			if err != nil {
				return err
			}
			if group <= 0 {
				return unsupportedSignal(name)
			}
			return signalProcess(group, name)
		},
		resize: func(cols, rows uint32) error {
			return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
		},
	}
	p.wait = func() (uint32, string) {
		code, sig := exitResult(cmd.Wait())
		p.mu.Lock()
		if !p.closed {
			killGroup()
			// 先传完退出前输出，再结束仍被后台进程持有的终端读取。
			terminal.SetReadDeadline(time.Now().Add(time.Second))
		}
		p.mu.Unlock()
		drained()
		return code, sig
	}
	return p, nil
}

// resumeCommand 在 Unix 无需额外恢复；pid 为已启动进程。
func resumeCommand(pid int) error { return nil }
