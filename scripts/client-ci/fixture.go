package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
)

// fixture 持有本次专属服务、认证文件、配置和日志。
type fixture struct {
	root, binary, addr, config, key, password string
	signer                                    ssh.Signer
	command                                   *exec.Cmd
	done                                      chan error
	log                                       *os.File
}

// newFixture 在 ctx 生命周期内创建 mode 专属服务，运行 binary。
func newFixture(ctx context.Context, mode, binary string) (*fixture, error) {
	root, err := filepath.Abs(filepath.Join("data", "client-ci", mode))
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	f := &fixture{root: root, binary: binary, key: filepath.Join(root, "identity"), config: filepath.Join(root, "ssh_config")}
	cleanup := true
	defer func() {
		if cleanup {
			f.close()
		}
	}()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f.signer, err = ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, err
	}
	key := pem.EncodeToMemory(block)
	secret := make([]byte, 24)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	f.password = hex.EncodeToString(secret)
	f.addr, err = freeAddress()
	if err != nil {
		return nil, err
	}
	values := map[string]string{"SSHDEV_LISTEN": f.addr, "SSHDEV_PASSWORD": f.password, "SSHDEV_AUTHORIZED_KEYS": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.signer.PublicKey()))), "SSHDEV_HOST_KEY": string(key), "SSHDEV_TEST_PASSWORD": f.password, "SSHDEV_CLIENT_KEY": string(key), "SSHDEV_INSECURE": "false"}
	envPath := filepath.Join(root, ".env")
	if err = godotenv.Write(values, envPath); err != nil {
		return nil, err
	}
	if err = os.Chmod(envPath, 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(f.key, key, 0600); err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		// Windows 忽略 Unix mode 位，显式移除继承权限并只允许当前用户读取私钥。
		current, e := user.Current()
		if e != nil {
			return nil, e
		}
		if output, e := exec.CommandContext(ctx, "icacls", f.key, "/inheritance:r", "/grant:r", "*"+current.Uid+":R").CombinedOutput(); e != nil {
			return nil, fmt.Errorf("设置私钥权限: %w: %s", e, output)
		}
	}
	_, port, _ := net.SplitHostPort(f.addr)
	known := filepath.Join(root, "known_hosts")
	if err = os.WriteFile(known, []byte("[127.0.0.1]:"+port+" "+string(ssh.MarshalAuthorizedKey(f.signer.PublicKey()))), 0600); err != nil {
		return nil, err
	}
	config := fmt.Sprintf("Host sshdev-ci\n HostName 127.0.0.1\n Port %s\n User client-ci\n IdentityFile %q\n UserKnownHostsFile %q\n StrictHostKeyChecking yes\n IdentitiesOnly yes\n BatchMode yes\n LogLevel ERROR\n", port, filepath.ToSlash(f.key), filepath.ToSlash(known))
	if err = os.WriteFile(f.config, []byte(config), 0600); err != nil {
		return nil, err
	}
	f.log, err = os.Create(filepath.Join(root, "server.log"))
	if err != nil {
		return nil, err
	}
	f.command = exec.CommandContext(ctx, binary, "run", "--env-file", envPath)
	f.command.Stdout = f.log
	f.command.Stderr = f.log
	if err = f.command.Start(); err != nil {
		return nil, err
	}
	f.done = make(chan error, 1)
	go func() { f.done <- f.command.Wait() }()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		connection, e := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{User: "client-ci", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.signer)}, HostKeyCallback: ssh.FixedHostKey(f.signer.PublicKey()), Timeout: time.Second})
		if e == nil {
			connection.Close()
			cleanup = false
			return f, nil
		}
		select {
		case e := <-f.done:
			f.done = nil
			return nil, fmt.Errorf("服务提前退出: %w", e)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("服务未就绪，详见 %s", filepath.Join(root, "server.log"))
}

// close 仅终止本次拥有的服务进程并关闭日志。
func (f *fixture) close() {
	if f.command != nil && f.command.Process != nil {
		f.command.Process.Kill()
	}
	if f.done != nil {
		<-f.done
		f.done = nil
	}
	if f.log != nil {
		f.log.Close()
	}
}

// freeAddress 申请并释放本机临时端口，供独占客户端进程使用。
func freeAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := listener.Addr().String()
	return addr, listener.Close()
}

// execute 在 ctx 下运行 name 和 args，保存客户端输出而不记录认证参数。
func (f *fixture) execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	logPath := filepath.Join(f.root, filepath.Base(name)+".log")
	file, e := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e == nil {
		file.Write(output)
		file.Close()
	}
	if err != nil {
		return output, fmt.Errorf("%s 执行失败: %w: %s", filepath.Base(name), err, output)
	}
	return output, nil
}

// remotePath 把 path 转为 Windows/Linux SFTP 通用绝对路径。
func remotePath(path string) string {
	path = filepath.ToSlash(path)
	if len(path) > 1 && path[1] == ':' {
		return "/" + path
	}
	return path
}
