package main

import (
	"context"
	"fmt"
	"github.com/117503445/sshdev/internal/types"
	"github.com/kardianos/service"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/117503445/sshdev/pkg/sshlib"
)

var cli struct {
	Run       CmdRun       `cmd:"" help:"Run SSH server" default:"1"`
	Install   CmdInstall   `cmd:"" help:"安装并启动系统服务"`
	Uninstall CmdUninstall `cmd:"" help:"卸载服务并保留配置"`
	Status    CmdStatus    `cmd:"" help:"查看系统服务状态"`
	Doctor    CmdDoctor    `cmd:"" help:"检查配置和监听状态"`
}

// CmdRun 配置前台运行或系统服务运行。
type CmdRun struct {
	ConfigOptions `embed:""`
	EnvFile       string `name:"env-file" help:"启动时加载的 .env 文件"`
	ServiceName   string `name:"service-name" hidden:""`
}

func (cmd *CmdRun) Run() error {
	if cmd.ServiceName != "" {
		program := &serviceProgram{command: cmd}
		svc, err := service.New(program, &service.Config{Name: cmd.ServiceName})
		if err != nil {
			return err
		}
		return svc.Run()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), osSignalToWatch()...)
	defer cancel()
	return cmd.run(ctx)
}

// run 按 cmd 配置运行 SSH 服务，ctx 取消时清理连接和隧道。
func (cmd *CmdRun) run(ctx context.Context) error {
	ctx = log.Logger.WithContext(ctx)
	log.Ctx(ctx).Info().Msg("CmdRun.Run() called, initializing configuration")

	resolved, err := resolveConfig(cmd.ConfigOptions, environmentValues())
	if err != nil {
		return err
	}
	cfg := resolved.Config
	enablePinggy := resolved.Pinggy
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

	log.Ctx(ctx).Info().Msg("Starting SSH server loop")
	err = server.Start(ctx)
	if pinggyCmd != nil && pinggyCmd.Process != nil {
		_ = pinggyCmd.Process.Kill()
	}
	return err
}

// defaultShell 按当前操作系统返回默认 shell。
func defaultShell(ctx context.Context) string {
	shell := types.DefaultShell()
	log.Ctx(ctx).Info().Str("shell", shell).Msg("使用默认 shell")
	return shell
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
