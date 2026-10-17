package sshlib_test

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWindowsShells 在 Windows 实际验证 PowerShell 和 cmd 的命令参数；t 为测试上下文。
func TestWindowsShells(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows shell 参数")
	}
	for _, name := range []string{"powershell.exe", "cmd.exe"} {
		t.Run(name, func(t *testing.T) {
			shell, err := exec.LookPath(name)
			if err != nil {
				t.Fatal(err)
			}
			_, c, _ := behaviorServer(t, shell)
			s, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			path := filepath.Join(t.TempDir(), "中文 文件.txt")
			if err = os.WriteFile(path, []byte("quoted space"), 0600); err != nil {
				t.Fatal(err)
			}
			command := "[Console]::Write([IO.File]::ReadAllText('" + strings.ReplaceAll(path, "'", "''") + "')); exit 12"
			if name == "cmd.exe" {
				command = `type "` + path + `" & exit /b 12`
			}
			output, err := s.Output(command)
			var exit *ssh.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 12 || strings.TrimSpace(string(output)) != "quoted space" {
				t.Fatalf("%s: %q (%v)", name, output, err)
			}
		})
	}
}

// TestWindowsPTYSize 验证 ConPTY 初始尺寸与运行期间窗口调整；t 为测试上下文。
func TestWindowsPTYSize(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ConPTY 尺寸")
	}
	_, c, _ := behaviorServer(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.RequestPty("xterm", 24, 80, nil); err != nil {
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
	output := make(chan string, 32)
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
	command := "[Console]::WriteLine('SIZE '+[Console]::WindowHeight+' '+[Console]::WindowWidth); [Console]::ReadLine() | Out-Null; [Console]::WriteLine('SIZE '+[Console]::WindowHeight+' '+[Console]::WindowWidth)"
	if err = s.Start(command); err != nil {
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
				t.Fatalf("未收到尺寸 %q: %q", want, text)
			}
		}
	}
	await("SIZE 24 80")
	if err = s.WindowChange(40, 120); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(input, "\r"); err != nil {
		t.Fatal(err)
	}
	await("SIZE 40 120")
}
