package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/117503445/sshdev/pkg/sshlib"
)

var cli struct {
	Run CmdRun `cmd:"" help:"Run SSH server" default:"1"`
}

type CmdRun struct {
	ListenAddr          string `name:"listen" help:"listen address" default:"0.0.0.0:2222" env:"SSHDEV_LISTEN"`
	HostKeyPath         string `name:"host-key" help:"host key file path" env:"SSHDEV_HOST_KEY_PATH"`
	HostKeyContent      string `name:"host-key-content" help:"host key content (PEM format)" env:"SSHDEV_HOST_KEY"`
	HostKeyBuiltin      bool   `name:"host-key-builtin" help:"use built-in host key" env:"SSHDEV_HOST_KEY_BUILTIN"`
	Password            string `name:"password" help:"password for authentication" env:"SSHDEV_PASSWORD"`
	AuthorizedKeysFiles string `name:"authorized-keys-files" help:"authorized keys file paths (colon-separated)" env:"SSHDEV_AUTHORIZED_KEYS_FILES"`
	AuthorizedKeys      string `name:"authorized-keys" help:"authorized keys content (newline-separated)" env:"SSHDEV_AUTHORIZED_KEYS"`
	Insecure            bool   `name:"insecure" help:"allow no-auth mode when password and public key auth are not configured" env:"SSHDEV_INSECURE"`
	Shell               string `name:"shell" help:"default shell (empty = current user's default)" env:"SSHDEV_SHELL"`
	ConfigJSON          string `name:"config-json" help:"JSON configuration" env:"SSHDEV_CONFIG_JSON"`
	Pinggy              bool   `name:"pinggy" help:"expose SSH server through a temporary anonymous Pinggy TCP tunnel" env:"SSHDEV_PINGGY"`
}

// JSONConfig 表示 JSON 配置结构。
type JSONConfig struct {
	ListenAddr          string `json:"listenAddr"`
	HostKeyPath         string `json:"hostKeyPath"`
	HostKeyContent      string `json:"hostKeyContent"`
	HostKeyBuiltin      bool   `json:"hostKeyBuiltin"`
	Password            string `json:"password"`
	AuthorizedKeysFiles string `json:"authorizedKeysFiles"`
	AuthorizedKeys      string `json:"authorizedKeys"`
	Insecure            bool   `json:"insecure"`
	Shell               string `json:"shell"`
	Pinggy              bool   `json:"pinggy"`
}

func (cmd *CmdRun) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = log.Logger.WithContext(ctx)
	log.Ctx(ctx).Info().Msg("CmdRun.Run() called, initializing configuration")

	cfg := &sshlib.Config{}
	var enablePinggy bool

	// 优先尝试从 JSON 配置加载。
	if cmd.ConfigJSON != "" {
		log.Ctx(ctx).Info().Msg("Loading configuration from JSON")
		var jsonCfg JSONConfig
		if err := json.Unmarshal([]byte(cmd.ConfigJSON), &jsonCfg); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to parse SSHDEV_CONFIG_JSON, ignoring")
		} else {
			applyJSONConfig(cfg, &jsonCfg)
			enablePinggy = jsonCfg.Pinggy
			log.Ctx(ctx).Info().Msg("JSON configuration applied")
		}
	}

	// 然后应用命令行和环境变量覆盖项。
	applyCLIConfig(cfg, cmd)
	if cmd.Pinggy {
		enablePinggy = true
	}
	log.Ctx(ctx).Info().Msg("CLI configuration applied")

	// 未显式配置 shell 时按当前系统选择默认值。
	if cfg.Shell == "" {
		cfg.Shell = defaultShell(ctx)
	}

	log.Ctx(ctx).Info().
		Str("shell", cfg.Shell).
		Str("listenAddr", cfg.ListenAddr).
		Bool("hostKeyBuiltin", cfg.HostKeyBuiltin).
		Bool("insecure", cfg.Insecure).
		Bool("pinggy", enablePinggy).
		Str("hostKeyPath", cfg.HostKeyPath).
		Bool("hasHostKeyContent", cfg.HostKeyContent != "").
		Msg("Configuration ready, validating")

	if err := cfg.Validate(ctx); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("shell", cfg.Shell).Msg("Configuration validation failed")
		return err
	}

	log.Ctx(ctx).Info().Msg("Configuration validated successfully")

	log.Ctx(ctx).Info().
		Str("listen", cfg.ListenAddr).
		Bool("passwordAuth", cfg.HasPasswordAuth()).
		Bool("publicKeyAuth", cfg.HasPublicKeyAuth()).
		Bool("insecure", cfg.Insecure).
		Str("shell", cfg.Shell).
		Msg("Starting SSH server")

	server, err := sshlib.NewServer(ctx, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Failed to create SSH server")
		return err
	}

	log.Ctx(ctx).Info().Msg("SSH server created, setting up signal handler")

	var pinggyCmd *exec.Cmd
	if enablePinggy {
		port, err := pinggyLocalPort(cfg.ListenAddr)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("listen", cfg.ListenAddr).Msg("Pinggy tunnel setup failed")
			return err
		}
		pinggyCmd, err = startPinggyTunnel(ctx, port)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("Pinggy tunnel setup failed")
			return err
		}
	}

	// 处理退出信号，确保 SSH 服务和 Pinggy 隧道一起停止。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, osSignalToWatch()...)

	go func() {
		<-sigCh
		log.Ctx(ctx).Info().Msg("Received shutdown signal")
		cancel()
		server.Stop()
		if pinggyCmd != nil && pinggyCmd.Process != nil {
			_ = pinggyCmd.Process.Kill()
		}
		os.Exit(0)
	}()

	log.Ctx(ctx).Info().Msg("Starting SSH server loop")
	err = server.Start(ctx)
	cancel()
	if pinggyCmd != nil && pinggyCmd.Process != nil {
		_ = pinggyCmd.Process.Kill()
	}
	return err
}

// applyJSONConfig 将 JSON 配置应用到配置对象。
func applyJSONConfig(cfg *sshlib.Config, jsonCfg *JSONConfig) {
	if jsonCfg.ListenAddr != "" {
		cfg.ListenAddr = jsonCfg.ListenAddr
	}
	if jsonCfg.HostKeyPath != "" {
		cfg.HostKeyPath = jsonCfg.HostKeyPath
	}
	if jsonCfg.HostKeyContent != "" {
		cfg.HostKeyContent = jsonCfg.HostKeyContent
	}
	if jsonCfg.HostKeyBuiltin {
		cfg.HostKeyBuiltin = jsonCfg.HostKeyBuiltin
	}
	if jsonCfg.Password != "" {
		cfg.Password = jsonCfg.Password
	}
	if jsonCfg.AuthorizedKeysFiles != "" {
		cfg.AuthorizedKeysFiles = jsonCfg.AuthorizedKeysFiles
	}
	if jsonCfg.AuthorizedKeys != "" {
		cfg.AuthorizedKeys = jsonCfg.AuthorizedKeys
	}
	if jsonCfg.Insecure {
		cfg.Insecure = jsonCfg.Insecure
	}
	if jsonCfg.Shell != "" {
		cfg.Shell = jsonCfg.Shell
	}
}

// applyCLIConfig 将命令行和环境变量配置应用到配置对象。
func applyCLIConfig(cfg *sshlib.Config, cmd *CmdRun) {
	if cmd.ListenAddr != "" {
		cfg.ListenAddr = cmd.ListenAddr
	}
	if cmd.HostKeyPath != "" {
		cfg.HostKeyPath = cmd.HostKeyPath
	}
	if cmd.HostKeyContent != "" {
		cfg.HostKeyContent = cmd.HostKeyContent
	}
	if cmd.HostKeyBuiltin {
		cfg.HostKeyBuiltin = cmd.HostKeyBuiltin
	}
	if cmd.Password != "" {
		cfg.Password = cmd.Password
	}
	if cmd.AuthorizedKeysFiles != "" {
		cfg.AuthorizedKeysFiles = cmd.AuthorizedKeysFiles
	}
	if cmd.AuthorizedKeys != "" {
		cfg.AuthorizedKeys = cmd.AuthorizedKeys
	}
	if cmd.Insecure {
		cfg.Insecure = cmd.Insecure
	}
	if cmd.Shell != "" {
		cfg.Shell = cmd.Shell
	}
}

// defaultShell 按当前操作系统返回默认 shell。
func defaultShell(ctx context.Context) string {
	// 优先使用 SHELL 环境变量。
	if shell := os.Getenv("SHELL"); shell != "" {
		log.Ctx(ctx).Info().Str("shell", shell).Msg("Using SHELL environment variable")
		return shell
	}

	switch runtime.GOOS {
	case "windows":
		// Windows 下优先使用 PowerShell Core。
		if pwshPath, err := exec.LookPath("pwsh"); err == nil {
			log.Ctx(ctx).Info().Str("shell", pwshPath).Msg("Using PowerShell Core (pwsh)")
			return pwshPath
		}
		// 其次尝试 Windows PowerShell。
		if psPath, err := exec.LookPath("powershell"); err == nil {
			log.Ctx(ctx).Info().Str("shell", psPath).Msg("Using Windows PowerShell")
			return psPath
		}
		// 再回退到系统目录里的 cmd.exe。
		if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
			cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")
			if _, err := os.Stat(cmdPath); err == nil {
				log.Ctx(ctx).Info().Str("shell", cmdPath).Msg("Using Windows cmd.exe (fallback)")
				return cmdPath
			}
		}
		log.Ctx(ctx).Info().Msg("Using cmd.exe from PATH (last resort)")
		return "cmd.exe"
	default:
		log.Ctx(ctx).Info().Msg("Using default /bin/sh")
		return "/bin/sh"
	}
}

// osSignalToWatch 按当前操作系统返回需要监听的退出信号。
func osSignalToWatch() []os.Signal {
	switch runtime.GOOS {
	case "windows":
		return []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
	default:
		return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	}
}

// pinggyLocalPort 从监听地址中提取可供 Pinggy 转发的本地端口。
func pinggyLocalPort(listenAddr string) (string, error) {
	addr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("无法解析监听地址 %q: %w", listenAddr, err)
	}
	if addr.Port == 0 {
		return "", fmt.Errorf("Pinggy 不支持从监听地址 %q 自动转发随机端口", listenAddr)
	}
	return strconv.Itoa(addr.Port), nil
}

// startPinggyTunnel 启动匿名 Pinggy TCP 隧道，并把 Pinggy 输出直接交给当前终端。
func startPinggyTunnel(ctx context.Context, localPort string) (*exec.Cmd, error) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil, fmt.Errorf("启用 --pinggy 需要系统 PATH 中存在 ssh 客户端: %w", err)
	}

	args := []string{
		"-p", "443",
		"-R", fmt.Sprintf("0:127.0.0.1:%s", localPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"tcp@a.pinggy.io",
	}
	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 Pinggy 隧道失败: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("localPort", localPort).
		Strs("args", args).
		Msg("Pinggy tunnel started")

	go func() {
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			log.Ctx(ctx).Warn().Err(err).Msg("Pinggy tunnel exited")
			return
		}
		log.Ctx(ctx).Info().Msg("Pinggy tunnel stopped")
	}()

	return cmd, nil
}
