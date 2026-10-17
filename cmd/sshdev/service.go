package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/117503445/sshdev/pkg/sshlib"
	"github.com/joho/godotenv"
	"github.com/kardianos/service"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// ServiceOptions 指定独立服务的名称和持久配置目录。
type ServiceOptions struct {
	Name      string `help:"服务名称" default:"sshdev"`
	ConfigDir string `help:"配置和服务程序目录"`
}

// CmdInstall 安装并启动系统服务，认证配置必须预先写入 .env。
type CmdInstall struct {
	ServiceOptions `embed:""`
}

// CmdUninstall 停止并卸载服务，保留配置与主机身份。
type CmdUninstall struct {
	ServiceOptions `embed:""`
}

// CmdStatus 输出结构化服务状态。
type CmdStatus struct {
	ServiceOptions `embed:""`
}

// CmdDoctor 检查配置、认证、shell、主机身份及监听状态。
type CmdDoctor struct {
	ServiceOptions `embed:""`
}

// directory 解析服务配置目录为绝对路径。
func (o ServiceOptions) directory() (string, error) {
	path := o.ConfigDir
	if path == "" {
		switch runtime.GOOS {
		case "windows":
			path = filepath.Join(os.Getenv("ProgramData"), "sshdev")
		case "darwin":
			path = "/Library/Application Support/sshdev"
		default:
			path = "/etc/sshdev"
		}
	}
	return filepath.Abs(path)
}

// serviceProgram 保存服务的配置、取消函数及后台执行结果。
type serviceProgram struct {
	command *CmdRun
	cancel  context.CancelFunc
	done    chan error
}

// Start 在 svc 的后台启动 SSH 服务；服务管理器不被监听循环阻塞。
func (p *serviceProgram) Start(svc service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = log.Logger.WithContext(ctx)
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() {
		err := p.command.run(ctx)
		p.done <- err
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("服务执行失败")
			os.Exit(1)
		}
	}()
	return nil
}

// Stop 停止 svc 的 SSH 会话并等待后台释放资源。
func (p *serviceProgram) Stop(svc service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	return <-p.done
}

// serviceConfig 构造使用 dir 内持久二进制及 .env 的服务配置；name 为系统服务名。
func serviceConfig(name, dir string) *service.Config {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	return &service.Config{Name: name, DisplayName: "sshdev (" + name + ")", Description: "sshdev SSH 与 SFTP 服务", Executable: filepath.Join(dir, "sshdev"+suffix), Arguments: []string{"run", "--env-file", filepath.Join(dir, ".env"), "--service-name", name}, WorkingDirectory: dir, Option: service.KeyValue{"OnFailure": "restart", "OnFailureDelayDuration": "5s", "Restart": "on-failure"}}
}

// manager 创建 o 指定的服务管理对象；program 为实际后台程序。
func (o ServiceOptions) manager(program service.Interface) (service.Service, error) {
	valid := len(o.Name) > 0 && len(o.Name) <= 100
	for _, ch := range o.Name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			valid = false
		}
	}
	if !valid {
		return nil, fmt.Errorf("无效服务名")
	}
	dir, err := o.directory()
	if err != nil {
		return nil, err
	}
	return service.New(program, serviceConfig(o.Name, dir))
}

// Run 校验配置，持久化程序和主机身份，然后安装并启动服务。
func (c *CmdInstall) Run() error {
	dir, err := c.directory()
	if err != nil {
		return err
	}
	values, err := godotenv.Read(filepath.Join(dir, ".env"))
	if err != nil {
		return fmt.Errorf("请先在 %s 配置认证: %w", filepath.Join(dir, ".env"), err)
	}
	if values["SSHDEV_PASSWORD"] == "" && values["SSHDEV_AUTHORIZED_KEYS"] == "" && values["SSHDEV_AUTHORIZED_KEYS_FILES"] == "" {
		return fmt.Errorf("安装常驻服务必须配置密码或公钥")
	}
	cfg := &sshlib.Config{Password: values["SSHDEV_PASSWORD"], AuthorizedKeys: values["SSHDEV_AUTHORIZED_KEYS"], AuthorizedKeysFiles: values["SSHDEV_AUTHORIZED_KEYS_FILES"], Shell: values["SSHDEV_SHELL"]}
	if err = cfg.Validate(context.Background()); err != nil {
		return err
	}
	svc, err := c.manager(nil)
	if err != nil {
		return err
	}
	if _, err = svc.Status(); !errors.Is(err, service.ErrNotInstalled) {
		if err != nil {
			return err
		}
		return fmt.Errorf("服务已存在，请先检查 status；不会覆盖现有服务")
	}
	if err = secureDirectory(dir); err != nil {
		return err
	}
	if err = secureFile(filepath.Join(dir, ".env")); err != nil {
		return err
	}
	keyPath := values["SSHDEV_HOST_KEY_PATH"]
	if values["SSHDEV_HOST_KEY_BUILTIN"] != "" {
		return fmt.Errorf("常驻服务请使用独有主机密钥，不能使用内置共用私钥")
	}
	if values["SSHDEV_HOST_KEY"] == "" {
		if keyPath == "" {
			keyPath = filepath.Join(dir, "host_key")
			values["SSHDEV_HOST_KEY_PATH"] = keyPath
		}
		if !filepath.IsAbs(keyPath) {
			return fmt.Errorf("服务主机密钥路径必须为绝对路径")
		}
		if err = ensureHostKey(keyPath); err != nil {
			return err
		}
	}
	values["SSHDEV_INSECURE"] = "false"
	if err = godotenv.Write(values, filepath.Join(dir, ".env")); err != nil {
		return err
	}
	if err = secureFile(filepath.Join(dir, ".env")); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	destination := serviceConfig(c.Name, dir).Executable
	if executable != destination {
		source, e := os.Open(executable)
		if e != nil {
			return e
		}
		defer source.Close()
		target, e := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
		if e != nil {
			return e
		}
		_, copyErr := io.Copy(target, source)
		closeErr := target.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = svc.Install(); err != nil {
		return err
	}
	listen := values["SSHDEV_LISTEN"]
	if listen == "" {
		listen = "0.0.0.0:2222"
	}
	if err = installFirewall(c.Name, destination, listen); err != nil {
		svc.Uninstall()
		return err
	}
	if err = svc.Start(); err != nil {
		return fmt.Errorf("服务已安装但启动失败: %w", err)
	}
	fmt.Printf("已安装并启动 %s，配置目录 %s\n", c.Name, dir)
	return nil
}

// Run 停止并卸载指定服务，保留密钥、配置和程序用于重新安装。
func (c *CmdUninstall) Run() error {
	svc, err := c.manager(nil)
	if err != nil {
		return err
	}
	status, err := svc.Status()
	if err != nil {
		return err
	}
	if status == service.StatusRunning {
		if err = svc.Stop(); err != nil {
			return err
		}
	}
	if err = svc.Uninstall(); err != nil {
		return err
	}
	if err = uninstallFirewall(c.Name); err != nil {
		return err
	}
	fmt.Println("已卸载服务，配置和主机密钥保留")
	return nil
}

// Run 输出指定服务的名称、状态、配置目录和版本。
func (c *CmdStatus) Run() error {
	svc, err := c.manager(nil)
	if err != nil {
		return err
	}
	state, err := svc.Status()
	status := "stopped"
	if errors.Is(err, service.ErrNotInstalled) {
		status = "not-installed"
	} else if err != nil {
		return err
	} else if state == service.StatusRunning {
		status = "running"
	}
	dir, _ := c.directory()
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"name": c.Name, "status": status, "configDir": dir, "version": Version})
}

// Run 自检指定目录中的 .env、认证、shell、主机密钥和本地 SSH 监听。
func (c *CmdDoctor) Run() error {
	dir, err := c.directory()
	if err != nil {
		return err
	}
	values, err := godotenv.Read(filepath.Join(dir, ".env"))
	if err != nil {
		return err
	}
	checks := map[string]any{"configDir": dir, "authentication": values["SSHDEV_PASSWORD"] != "" || values["SSHDEV_AUTHORIZED_KEYS"] != "" || values["SSHDEV_AUTHORIZED_KEYS_FILES"] != ""}
	shell := values["SSHDEV_SHELL"]
	if shell == "" {
		shell = defaultShell(context.Background())
	}
	_, shellErr := exec.LookPath(shell)
	checks["shell"] = shell
	checks["shellAvailable"] = shellErr == nil
	key := []byte(values["SSHDEV_HOST_KEY"])
	if len(key) == 0 {
		key, err = os.ReadFile(values["SSHDEV_HOST_KEY_PATH"])
	}
	var signer ssh.Signer
	if err == nil {
		signer, err = ssh.ParsePrivateKey(key)
	}
	checks["hostKeyValid"] = err == nil
	if err == nil {
		checks["hostFingerprint"] = ssh.FingerprintSHA256(signer.PublicKey())
	}
	addr := values["SSHDEV_LISTEN"]
	if addr == "" {
		addr = "127.0.0.1:2222"
	}
	host, port, e := net.SplitHostPort(addr)
	if e == nil && (host == "" || host == "0.0.0.0" || host == "::") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	conn, dialErr := net.DialTimeout("tcp", addr, time.Second)
	if dialErr == nil {
		conn.Close()
	}
	checks["listening"] = dialErr == nil
	if err = json.NewEncoder(os.Stdout).Encode(checks); err != nil {
		return err
	}
	if checks["authentication"] != true || checks["shellAvailable"] != true || checks["hostKeyValid"] != true || dialErr != nil {
		return fmt.Errorf("自检未通过，详见检查结果")
	}
	return nil
}

// ensureHostKey 在 path 首次生成独有密钥，已存在时严格验证而不覆盖。
func ensureHostKey(path string) error {
	data, err := os.ReadFile(path)
	if err == nil {
		_, err = ssh.ParsePrivateKey(data)
		return err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(pem.EncodeToMemory(block))
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
