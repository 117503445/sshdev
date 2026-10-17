//go:build !windows

package sshlib_test

import (
	"bufio"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestPTYForegroundSignal 验证 SSH INT 中断交互 shell 的前台子进程；t 为测试上下文。
func TestPTYForegroundSignal(t *testing.T) {
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	_, c, _ := behaviorServer(t, shell)
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	session.Stdout = writer
	session.Stderr = writer
	output := make(chan string, 64)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, e := reader.Read(buf)
			if n > 0 {
				output <- string(buf[:n])
			}
			if e != nil {
				return
			}
		}
	}()
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	// READY 由前台进程输出，确保发送信号时它已取得终端前台进程组。
	if _, err = io.WriteString(input, "sh -c 'echo SIGNAL_READY; exec sleep 60'\n"); err != nil {
		t.Fatal(err)
	}
	text := ""
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for !strings.Contains(text, "SIGNAL_READY") {
		select {
		case part := <-output:
			text += part
		case <-timer.C:
			t.Fatalf("前台进程未启动: %q", text)
		}
	}
	if err = session.Signal(ssh.SIGINT); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(input, "echo SIGNAL_OK; exit 0\n"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	for {
		select {
		case part := <-output:
			text += part
		case err = <-done:
			for len(output) > 0 {
				text += <-output
			}
			if err != nil || !strings.Contains(text, "SIGNAL_OK") {
				t.Fatalf("前台信号结果 %q (%v)", text, err)
			}
			return
		case <-timer.C:
			t.Fatalf("前台子进程未被中断: %q", text)
		}
	}
}

// TestPTYDisconnectCleanup 验证前台子进程运行期间关闭终端后服务能够停止；t 为测试上下文。
func TestPTYDisconnectCleanup(t *testing.T) {
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	srv, c, _ := behaviorServer(t, shell)
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(input, "sh -c 'echo DISCONNECT_READY; exec sleep 60'\n"); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	go func() {
		reader := bufio.NewReader(stdout)
		for {
			line, e := reader.ReadString('\n')
			if strings.Contains(line, "DISCONNECT_READY") {
				close(ready)
				return
			}
			if e != nil {
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("前台进程未启动")
	}
	session.Close()
	done := make(chan struct{})
	go func() { srv.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PTY 断线后服务停止被阻塞")
	}
}
