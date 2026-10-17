package sshlib_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/117503445/sshdev/pkg/sshlib"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testShell 返回测试平台可用的 shell。
func testShell() string {
	if runtime.GOOS == "windows" {
		p, _ := exec.LookPath("powershell.exe")
		return p
	}
	return "/bin/sh"
}

// behaviorServer 为 t 启动独占服务，返回服务、客户端和地址。
func behaviorServer(t *testing.T) (sshlib.Server, *ssh.Client, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := sshlib.NewServer(context.Background(), &sshlib.Config{ListenAddr: addr, Password: "test-only", Shell: testShell()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start(context.Background()) }()
	var client *ssh.Client
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("test-only")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		srv.Stop()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		srv.Stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return srv, client, addr
}

// TestExecStreams 验证退出码、分离输出及客户端未关闭 stdin 时仍能退出；t 为测试上下文。
func TestExecStreams(t *testing.T) {
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, stderr bytes.Buffer
	s.Stdout = &out
	s.Stderr = &stderr
	input, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	command := "printf stdout; printf stderr >&2; exit 7"
	if runtime.GOOS == "windows" {
		command = "[Console]::Out.Write('stdout'); [Console]::Error.Write('stderr'); exit 7"
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(command) }()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stdin 未关闭时命令无法退出")
	}
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 {
		t.Fatalf("退出码: %v", err)
	}
	if out.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("输出被混合: stdout=%q stderr=%q", out.String(), stderr.String())
	}
}

// TestSFTP 验证中文空格路径、大文件哈希、目录、重命名和删除；t 为测试上下文。
func TestSFTP(t *testing.T) {
	_, c, _ := behaviorServer(t)
	sc, err := sftp.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	root := filepath.ToSlash(t.TempDir())
	if runtime.GOOS == "windows" {
		root = "/" + root
	}
	dir := root + "/中文 空格"
	if err = sc.Mkdir(dir); err != nil {
		t.Fatal(err)
	}
	name := dir + "/内容.bin"
	data := bytes.Repeat([]byte("文件\x00\xff"), 300000)
	f, err := sc.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = sc.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(data) != sha256.Sum256(read) {
		t.Fatal("文件哈希不符")
	}
	if err = sc.Rename(name, name+".new"); err != nil {
		t.Fatal(err)
	}
	entries, err := sc.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("目录结果 %v %v", entries, err)
	}
	if err = sc.Remove(name + ".new"); err != nil {
		t.Fatal(err)
	}
	if err = sc.RemoveDirectory(dir); err != nil {
		t.Fatal(err)
	}
}

// TestStopActiveConnections 验证停止服务能关闭已认证会话和未完成握手；t 为测试上下文。
func TestStopActiveConnections(t *testing.T) {
	srv, c, addr := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	command := "sleep 60"
	if runtime.GOOS == "windows" {
		command = "Start-Sleep 60"
	}
	if err = s.Start(command); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	done := make(chan struct{})
	go func() { srv.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop 未清理活动连接")
	}
	// 再次停止必须安全。
	srv.Stop()
}

// TestPTYSizeAndSignal 验证 Unix 初始尺寸、窗口变更及信号传递；t 为测试上下文。
func TestPTYSizeAndSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix stty 与信号语义")
	}
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	s.Stdout = w
	s.Stderr = w
	if err = s.Start("stty size; trap 'echo resized; stty size' WINCH; trap 'exit 23' TERM; echo ready; while :; do sleep 0.1; done"); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 32)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			if n > 0 {
				lines <- string(buf[:n])
			}
			if e != nil {
				return
			}
		}
	}()
	accumulated := ""
	await := func(want string) {
		t.Helper()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for !strings.Contains(accumulated, want) {
			select {
			case line := <-lines:
				accumulated += line
			case <-timer.C:
				t.Fatalf("未收到 %q: %q", want, accumulated)
			}
		}
	}
	await("24 80")
	await("ready")
	if err = s.WindowChange(40, 120); err != nil {
		t.Fatal(err)
	}
	await("40 120")
	if err = s.Signal(ssh.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err = <-done:
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.ExitStatus() != 23 {
			t.Fatalf("信号退出: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("信号未送达")
	}
}

// TestTerminalInteractive 验证交互终端的 Ctrl+C 和退出；t 为测试上下文。
func TestTerminalInteractive(t *testing.T) {
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	input, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	s.Stdout = writer
	s.Stderr = writer
	if err = s.Shell(); err != nil {
		t.Fatal(err)
	}
	output := make(chan string, 64)
	go func() {
		buf := make([]byte, 4096)
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
	command := "sleep 60\n"
	ending := "echo TERMINAL_OK; exit 9\n"
	if runtime.GOOS == "windows" {
		command = "Start-Sleep 60\r"
		ending = "Write-Output TERMINAL_OK; exit 9\r"
	}
	if _, err = io.WriteString(input, command); err != nil {
		t.Fatal(err)
	}
	// 等待 shell 启动并进入阻塞命令，然后从终端送 Ctrl+C。
	time.Sleep(time.Second)
	if _, err = input.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err = io.WriteString(input, ending); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	text := ""
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case part := <-output:
			text += part
		case err = <-done:
			for len(output) > 0 {
				text += <-output
			}
			if !strings.Contains(text, "TERMINAL_OK") {
				t.Fatalf("终端输出 %q (%v)", text, err)
			}
			return
		case <-timer.C:
			t.Fatalf("Ctrl+C 后未退出: %q", text)
		}
	}
}

// TestDisconnectKillsCommand 验证断线后命令不会继续写文件；t 为测试上下文。
func TestDisconnectKillsCommand(t *testing.T) {
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "should-not-exist")
	command := fmt.Sprintf("sleep 1; echo leaked > '%s'", target)
	if runtime.GOOS == "windows" {
		command = fmt.Sprintf("Start-Sleep 1; Set-Content -LiteralPath '%s' -Value leaked", strings.ReplaceAll(target, "'", "''"))
	}
	if err = s.Start(command); err != nil {
		t.Fatal(err)
	}
	c.Close()
	time.Sleep(1500 * time.Millisecond)
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("断线后进程仍执行: %v", err)
	}
}
