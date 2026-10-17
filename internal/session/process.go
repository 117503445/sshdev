package session

import (
	"io"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// startProcess 根据 shell、command、isExec、env 和 term 启动进程并连接 ch。
func startProcess(ch ssh.Channel, shell, command string, isExec bool, env []string, term *terminalRequest) (*process, error) {
	cmd := exec.Command(shell, shellArgs(shell, command, isExec)...)
	cmd.Env = env
	cmd.WaitDelay = time.Second
	if term != nil {
		cmd.Env = append(cmd.Env, "TERM="+term.Term)
		return startTerminal(ch, cmd, term)
	}
	prepareCommand(cmd)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	if err = cmd.Start(); err != nil {
		input.Close()
		return nil, err
	}
	kill, err := manageProcess(cmd.Process.Pid)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		input.Close()
		return nil, err
	}
	if err = resumeCommand(cmd.Process.Pid); err != nil {
		kill()
		cmd.Wait()
		input.Close()
		return nil, err
	}
	go func() { _, _ = io.Copy(input, ch); input.Close() }()
	return &process{
		done: make(chan struct{}), kill: func() { kill(); input.Close() },
		signal: func(name string) error { return signalProcess(cmd.Process.Pid, name) },
		resize: func(uint32, uint32) error { return unsupportedSignal("非终端会话") },
		wait:   func() (uint32, string) { return exitResult(cmd.Wait()) },
	}, nil
}

// copyTerminal 将 input 的终端输出传到 ch；返回等待复制结束的函数。
func copyTerminal(ch ssh.Channel, input io.ReadWriter) func() {
	var output sync.WaitGroup
	output.Add(1)
	go func() { defer output.Done(); _, _ = io.Copy(ch, input) }()
	go func() { _, _ = io.Copy(input, ch) }()
	return output.Wait
}
