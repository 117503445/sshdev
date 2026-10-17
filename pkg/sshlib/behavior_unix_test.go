//go:build !windows

package sshlib_test

import (
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
