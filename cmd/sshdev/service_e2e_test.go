package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
)

// TestServiceLifecycle 在明确启用的隔离 CI 验证安装、登录、自检和卸载；t 为测试上下文。
func TestServiceLifecycle(t *testing.T) {
	if os.Getenv("SSHDEV_SERVICE_TEST") != "1" {
		t.Skip("仅在隔离系统服务验收环境运行")
	}
	binary := os.Getenv("SSHDEV_TEST_BINARY")
	if binary == "" {
		t.Fatal("缺少 SSHDEV_TEST_BINARY")
	}
	dir := t.TempDir()
	name := fmt.Sprintf("sshdev-ci-%d", os.Getpid())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"SSHDEV_PASSWORD": "service-test-only", "SSHDEV_AUTHORIZED_KEYS": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(mustPublicKey(t, public)))), "SSHDEV_LISTEN": addr}
	if err = godotenv.Write(values, filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	run := func(command string) ([]byte, error) {
		return exec.Command(binary, command, "--name", name, "--config-dir", dir).CombinedOutput()
	}
	t.Cleanup(func() {
		out, e := run("uninstall")
		if e != nil {
			t.Logf("清理服务: %s (%v)", out, e)
		}
	})
	if output, e := run("install"); e != nil {
		t.Fatalf("安装失败: %s (%v)", output, e)
	}
	if output, e := run("install"); e == nil {
		t.Fatalf("重复安装应拒绝覆盖: %s", output)
	}
	var autoStart *exec.Cmd
	expectedStart := "enabled"
	if runtime.GOOS == "windows" {
		expectedStart = "Automatic"
		autoStart = exec.Command("powershell.exe", "-NoProfile", "-Command", "(Get-Service -Name '"+name+"').StartType")
	} else {
		autoStart = exec.Command("systemctl", "is-enabled", name)
	}
	if output, e := autoStart.CombinedOutput(); e != nil || !strings.Contains(string(output), expectedStart) {
		t.Fatalf("服务未启用开机启动: %s (%v)", output, e)
	}
	dial := func(auth ssh.AuthMethod, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{auth}, HostKeyCallback: hostKey, Timeout: time.Second})
	}
	deadline := time.Now().Add(30 * time.Second)
	var client *ssh.Client
	for time.Now().Before(deadline) {
		client, err = dial(ssh.Password("service-test-only"), ssh.InsecureIgnoreHostKey())
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("服务未监听: %v", err)
	}
	client.Close()
	keyData, err := os.ReadFile(filepath.Join(dir, "host_key"))
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	if client, err = dial(ssh.PublicKeys(signer), ssh.FixedHostKey(hostSigner.PublicKey())); err != nil {
		t.Fatal(err)
	}
	client.Close()
	for _, password := range []string{"", "wrong"} {
		if client, e := dial(ssh.Password(password), ssh.FixedHostKey(hostSigner.PublicKey())); e == nil {
			client.Close()
			t.Fatal("错误或空密码被接受")
		}
	}
	_, unknownPrivate, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	unknownSigner, e := ssh.NewSignerFromKey(unknownPrivate)
	if e != nil {
		t.Fatal(e)
	}
	if client, e := dial(ssh.PublicKeys(unknownSigner), ssh.FixedHostKey(hostSigner.PublicKey())); e == nil {
		client.Close()
		t.Fatal("未授权公钥被接受")
	}
	if output, e := run("doctor"); e != nil || !bytes.Contains(output, []byte("hostFingerprint")) {
		t.Fatalf("自检失败: %s (%v)", output, e)
	}
	output, e := run("status")
	if e != nil || !bytes.Contains(output, []byte(`"status":"running"`)) {
		t.Fatalf("状态错误: %s (%v)", output, e)
	}
	// 直接杀死服务进程，验证系统服务管理器实际恢复，而非仅检查配置。
	installed := filepath.Join(dir, "sshdev")
	if runtime.GOOS == "windows" {
		installed += ".exe"
	}
	var kill *exec.Cmd
	if runtime.GOOS == "windows" {
		kill = exec.Command("powershell.exe", "-NoProfile", "-Command", fmt.Sprintf("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq '%s' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }", strings.ReplaceAll(installed, "'", "''")))
	} else {
		kill = exec.Command("systemctl", "kill", "--signal=KILL", name)
	}
	if output, e = kill.CombinedOutput(); e != nil {
		t.Fatalf("杀死服务失败: %s (%v)", output, e)
	}
	deadline = time.Now().Add(150 * time.Second)
	restarted := false
	for time.Now().Before(deadline) {
		client, e = dial(ssh.Password("service-test-only"), ssh.FixedHostKey(hostSigner.PublicKey()))
		if e == nil {
			client.Close()
			restarted = true
			break
		}
		time.Sleep(time.Second)
	}
	if !restarted {
		t.Fatal("服务没有自动恢复")
	}
	if output, e = run("uninstall"); e != nil {
		t.Fatalf("卸载失败: %s (%v)", output, e)
	}
	if _, err = os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Fatal("卸载删除配置")
	}
	after, err := os.ReadFile(filepath.Join(dir, "host_key"))
	if err != nil || !bytes.Equal(keyData, after) {
		t.Fatal("卸载改变主机密钥")
	}
	// Windows 删除服务是异步完成的，等待状态收敛。
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, e = run("status")
		if e == nil && bytes.Contains(output, []byte(`"status":"not-installed"`)) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("服务仍存在: %s (%v)", output, e)
}

// mustPublicKey 将 key 转为 SSH 公钥，失败时终止 t。
func mustPublicKey(t *testing.T, key ed25519.PublicKey) ssh.PublicKey {
	t.Helper()
	public, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

// TestCLIConfigFile 验证发布程序主动加载 .env 并拒绝无效配置；t 为测试上下文。
func TestCLIConfigFile(t *testing.T) {
	binary := os.Getenv("SSHDEV_TEST_BINARY")
	if binary == "" {
		t.Skip("需要发布程序路径")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, ".env")
	if err := os.WriteFile(file, []byte("SSHDEV_INSECURE=false\nSSHDEV_SHELL=/missing/shell\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "run", "--env-file", file).CombinedOutput()
	if err == nil {
		t.Fatal("无认证配置被接受")
	}
	if bytes.Contains(out, []byte(`"Password"`)) || bytes.Contains(out, []byte(`"HostKeyContent"`)) {
		t.Fatal("日志输出完整敏感配置")
	}
}

// TestDoctorInvalidConfig 验证自检明确返回失败且不泄露密码；t 为测试上下文。
func TestDoctorInvalidConfig(t *testing.T) {
	binary := os.Getenv("SSHDEV_TEST_BINARY")
	if binary == "" {
		t.Skip("需要发布程序路径")
	}
	dir := t.TempDir()
	if err := godotenv.Write(map[string]string{"SSHDEV_PASSWORD": "do-not-print-me", "SSHDEV_HOST_KEY_PATH": filepath.Join(dir, "missing")}, filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "doctor", "--config-dir", dir).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || bytes.Contains(out, []byte("do-not-print-me")) {
		t.Fatalf("诊断结果: %s (%v)", out, err)
	}
	// 确保第一行是可解析的诊断对象。
	decoder := json.NewDecoder(bytes.NewReader(out))
	var report map[string]any
	if err = decoder.Decode(&report); err != nil && err != io.EOF {
		t.Fatal(err)
	}
}
