package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/117503445/sshdev/embedded"
	"github.com/117503445/sshdev/internal/auth"
	"golang.org/x/crypto/ssh"
)

// CmdDoctor 核验共享配置、授权公钥、SSH 握手、主机指纹及实际运行版本。
type CmdDoctor struct {
	ServiceOptions  `embed:""`
	ConfigOptions   `embed:""`
	ExpectedVersion string        `help:"期望的运行版本，默认当前程序版本"`
	Identity        string        `help:"用于额外验证公钥登录的私钥路径"`
	Timeout         time.Duration `help:"SSH 连接及握手总超时" default:"10s"`
}

// replayConnection 在 conn 读取版本后重放前缀，让标准 SSH 客户端继续完整握手。
type replayConnection struct {
	net.Conn
	reader io.Reader
}

// Read 从保留前缀及后续连接读取 data。
func (c *replayConnection) Read(data []byte) (int, error) { return c.reader.Read(data) }

// readSSHVersion 从 conn 读取有界的 SSH 版本行，返回可重放连接和版本。
func readSSHVersion(conn net.Conn) (net.Conn, string, error) {
	reader := bufio.NewReaderSize(conn, 512)
	var prefix bytes.Buffer
	for prefix.Len() < 8192 {
		line, err := reader.ReadSlice('\n')
		prefix.Write(line)
		if err != nil {
			return nil, "", fmt.Errorf("读取 SSH 标识失败: %w", err)
		}
		if bytes.HasPrefix(line, []byte("SSH-")) {
			return &replayConnection{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix.Bytes()), reader)}, strings.TrimSpace(string(line)), nil
		}
	}
	return nil, "", fmt.Errorf("SSH 标识前缀过长")
}

// Run 对独立配置执行诊断，所有失败都输出结构化结果并返回非零状态。
func (c *CmdDoctor) Run() error {
	dir, err := c.directory()
	if err != nil {
		return err
	}
	_, values, err := serviceValues(filepath.Join(dir, ".env"))
	if err != nil {
		return err
	}
	resolved, err := resolveConfig(c.ConfigOptions, values)
	if err != nil {
		return err
	}
	cfg := resolved.Config
	checks := map[string]any{"configDir": dir, "authentication": cfg.HasPasswordAuth() || cfg.HasPublicKeyAuth(), "expectedVersion": c.ExpectedVersion}
	if c.ExpectedVersion == "" {
		c.ExpectedVersion = Version
		checks["expectedVersion"] = Version
	}
	validationErr := cfg.Validate(context.Background())
	checks["shell"] = cfg.Shell
	checks["shellAvailable"] = validationErr == nil
	count, keyErr := auth.ValidateAuthorizedKeys(cfg.AuthorizedKeysFiles, cfg.AuthorizedKeys)
	checks["authorizedKeysValid"] = keyErr == nil
	checks["authorizedKeyCount"] = count
	if keyErr != nil {
		checks["authorizedKeysError"] = keyErr.Error()
	}
	key := []byte(cfg.HostKeyContent)
	if len(key) == 0 {
		if cfg.HostKeyBuiltin {
			key = []byte(embedded.HostKey)
		} else {
			key, err = os.ReadFile(cfg.HostKeyPath)
		}
	}
	var signer ssh.Signer
	if err == nil {
		signer, err = ssh.ParsePrivateKey(key)
	}
	checks["hostKeyValid"] = err == nil
	if err == nil {
		checks["hostFingerprint"] = ssh.FingerprintSHA256(signer.PublicKey())
	}
	host, port, _ := net.SplitHostPort(cfg.ListenAddr)
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	addr := net.JoinHostPort(host, port)
	if c.Timeout <= 0 {
		return fmt.Errorf("超时必须大于零")
	}
	conn, dialErr := net.DialTimeout("tcp", addr, c.Timeout)
	checks["listening"] = dialErr == nil
	if dialErr == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(c.Timeout))
		transport, banner, readErr := readSSHVersion(conn)
		if readErr == nil && signer != nil {
			checks["runningVersion"] = strings.TrimPrefix(banner, "SSH-2.0-sshdev_")
			checks["versionMatches"] = banner == "SSH-2.0-sshdev_"+c.ExpectedVersion
			clientConfig := &ssh.ClientConfig{User: "sshdev-doctor", HostKeyCallback: func(_ string, _ net.Addr, public ssh.PublicKey) error {
				same := bytes.Equal(public.Marshal(), signer.PublicKey().Marshal())
				checks["hostKeyMatches"] = same
				if !same {
					return fmt.Errorf("主机指纹不匹配")
				}
				checks["sshVerified"] = true
				return nil
			}}
			if cfg.Password != "" {
				clientConfig.Auth = append(clientConfig.Auth, ssh.Password(cfg.Password))
			}
			if c.Identity != "" {
				private, e := os.ReadFile(c.Identity)
				if e != nil {
					return e
				}
				identity, e := ssh.ParsePrivateKey(private)
				if e != nil {
					return e
				}
				clientConfig.Auth = append(clientConfig.Auth, ssh.PublicKeys(identity))
			}
			connection, _, _, handshakeErr := ssh.NewClientConn(transport, addr, clientConfig)
			checks["authenticationVerified"] = handshakeErr == nil
			if connection != nil {
				connection.Close()
			}
			if handshakeErr != nil && checks["sshVerified"] != true {
				checks["sshError"] = handshakeErr.Error()
			}
		} else if readErr != nil {
			checks["sshError"] = readErr.Error()
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(checks); err != nil {
		return err
	}
	authenticated := true
	if cfg.Password != "" || c.Identity != "" {
		authenticated = checks["authenticationVerified"] == true
	}
	if checks["authentication"] != true || validationErr != nil || keyErr != nil || checks["hostKeyValid"] != true || checks["sshVerified"] != true || checks["hostKeyMatches"] != true || checks["versionMatches"] != true || !authenticated {
		return fmt.Errorf("SSH 自检未通过，详见检查结果")
	}
	return nil
}
