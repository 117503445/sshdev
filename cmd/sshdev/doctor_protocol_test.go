package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/117503445/sshdev/pkg/sshlib"
	"github.com/joho/godotenv"
)

// doctorFixture 为 t 建立独立配置与主机密钥，返回目录和配置变量。
func doctorFixture(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "host_key")
	if err := ensureHostKey(key); err != nil {
		t.Fatal(err)
	}
	return dir, map[string]string{"SSHDEV_PASSWORD": "doctor-test-only", "SSHDEV_HOST_KEY_PATH": key}
}

// startDoctorSSH 为 t 启动使用 values 和 version 的真实 SSH 服务，返回监听地址。
func startDoctorSSH(t *testing.T, values map[string]string, version string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	server, err := sshlib.NewServer(context.Background(), &sshlib.Config{ListenAddr: addr, HostKeyPath: values["SSHDEV_HOST_KEY_PATH"], Password: values["SSHDEV_PASSWORD"], Version: version})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, e := net.DialTimeout("tcp", addr, time.Millisecond*50)
		if e == nil {
			conn.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SSH未启动")
	return ""
}

// runDoctorBinary 调用 binary 对 dir 自检，并返回 JSON 结果和执行错误；t 为测试上下文。
func runDoctorBinary(t *testing.T, binary, dir string, values map[string]string) (map[string]any, error) {
	t.Helper()
	if err := godotenv.Write(values, filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "doctor", "--config-dir", dir).CombinedOutput()
	var report map[string]any
	if e := json.NewDecoder(bytes.NewReader(output)).Decode(&report); e != nil {
		t.Fatalf("诊断结果不是JSON: %s (%v)", output, e)
	}
	return report, err
}

// TestDoctorProtocol 验证真实 SSH、假 TCP、错误主机密钥、版本与授权公钥；t 为测试上下文。
func TestDoctorProtocol(t *testing.T) {
	binary := os.Getenv("SSHDEV_TEST_BINARY")
	if binary == "" {
		t.Skip("需要发布程序路径")
	}
	t.Run("普通TCP不能通过", func(t *testing.T) {
		dir, values := doctorFixture(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
				conn.Close()
			}
		}()
		values["SSHDEV_LISTEN"] = listener.Addr().String()
		if _, err = runDoctorBinary(t, binary, dir, values); err == nil {
			t.Fatal("非SSH服务被误判正常")
		}
	})
	t.Run("真实SSH通过", func(t *testing.T) {
		dir, values := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, values, "dev")
		report, err := runDoctorBinary(t, binary, dir, values)
		if err != nil || report["sshVerified"] != true || report["runningVersion"] != "dev" {
			t.Fatalf("真实SSH检查失败: %v (%v)", report, err)
		}
	})
	t.Run("主机密钥不匹配", func(t *testing.T) {
		dir, values := doctorFixture(t)
		_, other := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, other, "dev")
		if _, err := runDoctorBinary(t, binary, dir, values); err == nil {
			t.Fatal("主机指纹错误被接受")
		}
	})
	t.Run("运行版本不匹配", func(t *testing.T) {
		dir, values := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, values, "other-version")
		if _, err := runDoctorBinary(t, binary, dir, values); err == nil {
			t.Fatal("运行版本错误被接受")
		}
	})
	t.Run("无效授权公钥", func(t *testing.T) {
		dir, values := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, values, "dev")
		values["SSHDEV_AUTHORIZED_KEYS"] = "invalid-key"
		if _, err := runDoctorBinary(t, binary, dir, values); err == nil {
			t.Fatal("无效授权公钥被接受")
		}
	})
	t.Run("错误密码", func(t *testing.T) {
		dir, values := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, values, "dev")
		values["SSHDEV_PASSWORD"] = "wrong"
		if report, err := runDoctorBinary(t, binary, dir, values); err == nil || report["authenticationVerified"] != false {
			t.Fatalf("错误密码没有拒绝: %v (%v)", report, err)
		}
	})
	t.Run("授权文件不存在", func(t *testing.T) {
		dir, values := doctorFixture(t)
		values["SSHDEV_LISTEN"] = startDoctorSSH(t, values, "dev")
		values["SSHDEV_AUTHORIZED_KEYS_FILES"] = filepath.Join(dir, "missing_keys")
		if report, err := runDoctorBinary(t, binary, dir, values); err == nil || report["authorizedKeysValid"] != false {
			t.Fatalf("不可读授权文件没有拒绝: %v (%v)", report, err)
		}
	})
}
