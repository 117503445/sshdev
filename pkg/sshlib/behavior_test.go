package sshlib_test

import (
	"bufio"
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
func behaviorServer(t *testing.T, shells ...string) (sshlib.Server, *ssh.Client, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	shell := testShell()
	if len(shells) > 0 {
		shell = shells[0]
	}
	srv, err := sshlib.NewServer(context.Background(), &sshlib.Config{ListenAddr: addr, Password: "test-only", Shell: shell})
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
	command := "PS1='SSHDEV_READY> '; sh -c 'echo TERMINAL_BLOCKING; exec sleep 60'\n"
	ending := "echo TERMINAL_OK; exit 9\n"
	if runtime.GOOS == "windows" {
		command = "function prompt { 'SSHDEV_' + 'READY> ' }; Write-Output ('TERMINAL_' + 'BLOCKING'); Start-Sleep 60\r"
		ending = "Write-Output ('TERMINAL_' + 'OK'); exit 9\r"
	}
	if _, err = io.WriteString(input, command); err != nil {
		t.Fatal(err)
	}
	text := ""
	await := func(want string) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for !strings.Contains(text, want) {
			select {
			case part := <-output:
				text += part
			case <-timer.C:
				t.Fatalf("未收到终端状态 %q: %q", want, text)
			}
		}
	}
	// 根据实际输出同步，避免 PowerShell 仍在处理取消时丢弃下一条输入。
	await("TERMINAL_BLOCKING")
	if _, err = input.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	await("SSHDEV_READY> ")
	if _, err = io.WriteString(input, ending); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
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
			var exit *ssh.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 9 {
				t.Fatalf("交互终端退出码错误: %v", err)
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

// TestForwardingStop 验证活跃转发和动态远端端口在服务停止时释放；t 为测试上下文。
func TestForwardingStop(t *testing.T) {
	srv, c, _ := behaviorServer(t)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, e := backend.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	tunnel, err := c.Dial("tcp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	peer := <-accepted
	defer peer.Close()
	remote, err := c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr := remote.Addr().String()
	if err = remote.Close(); err != nil {
		t.Fatal(err)
	}
	// Close 返回之前 cancel-tcpip-forward 应已解除实际分配的端口。
	probe, err := net.Listen("tcp", remoteAddr)
	if err != nil {
		t.Fatalf("动态转发端口未释放: %v", err)
	}
	probe.Close()
	done := make(chan struct{})
	go func() { srv.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("活跃转发阻塞服务停止")
	}
}

// TestExecSignal 验证 Unix 被信号终止时的 SSH 退出结果；t 为测试上下文。
func TestExecSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX 退出信号")
	}
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start("sleep 60"); err != nil {
		t.Fatal(err)
	}
	if err = s.Signal(ssh.SIGKILL); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err = <-done:
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.Signal() != "KILL" || exit.ExitStatus() != 137 {
			t.Fatalf("退出结果错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("信号退出超时")
	}
}

// TestPTYDisconnectCleanup 验证前台子进程运行期间关闭终端后服务能够停止；t 为测试上下文。
func TestPTYDisconnectCleanup(t *testing.T) {
	shell := testShell()
	var err error
	if runtime.GOOS != "windows" {
		shell, err = exec.LookPath("bash")
		if err != nil {
			t.Fatal(err)
		}
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
	command := "sh -c 'echo DISCONNECT_READY; exec sleep 60'\n"
	if runtime.GOOS == "windows" {
		command = "Write-Output ('DISCONNECT_' + 'READY'); Start-Sleep 60\r"
	}
	if _, err = io.WriteString(input, command); err != nil {
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
