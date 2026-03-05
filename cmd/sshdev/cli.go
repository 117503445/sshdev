package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
	Shell               string `name:"shell" help:"default shell (empty = current user's default)" env:"SSHDEV_SHELL"`
	ConfigJSON          string `name:"config-json" help:"JSON configuration" env:"SSHDEV_CONFIG_JSON"`
}

// JSONConfig represents the JSON configuration structure
type JSONConfig struct {
	ListenAddr          string `json:"listenAddr"`
	HostKeyPath         string `json:"hostKeyPath"`
	HostKeyContent      string `json:"hostKeyContent"`
	HostKeyBuiltin      bool   `json:"hostKeyBuiltin"`
	Password            string `json:"password"`
	AuthorizedKeysFiles string `json:"authorizedKeysFiles"`
	AuthorizedKeys      string `json:"authorizedKeys"`
	Shell               string `json:"shell"`
}

func (cmd *CmdRun) Run() error {
	ctx := context.Background()
	ctx = log.Logger.WithContext(ctx)
	log.Ctx(ctx).Info().Msg("CmdRun.Run() called, initializing configuration")

	cfg := &sshlib.Config{}

	// First, try to load from JSON config
	if cmd.ConfigJSON != "" {
		log.Ctx(ctx).Info().Msg("Loading configuration from JSON")
		var jsonCfg JSONConfig
		if err := json.Unmarshal([]byte(cmd.ConfigJSON), &jsonCfg); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("failed to parse SSHDEV_CONFIG_JSON, ignoring")
		} else {
			applyJSONConfig(cfg, &jsonCfg)
			log.Ctx(ctx).Info().Msg("JSON configuration applied")
		}
	}

	// Then, apply command line / env overrides (these take precedence)
	applyCLIConfig(cfg, cmd)
	log.Ctx(ctx).Info().Msg("CLI configuration applied")

	// Set default shell based on OS if still empty
	if cfg.Shell == "" {
		cfg.Shell = defaultShell(ctx)
	}

	log.Ctx(ctx).Info().
		Str("shell", cfg.Shell).
		Str("listenAddr", cfg.ListenAddr).
		Bool("hostKeyBuiltin", cfg.HostKeyBuiltin).
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
		Str("shell", cfg.Shell).
		Msg("Starting SSH server")

	server, err := sshlib.NewServer(ctx, cfg)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Failed to create SSH server")
		return err
	}

	log.Ctx(ctx).Info().Msg("SSH server created, setting up signal handler")

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, osSignalToWatch()...)

	go func() {
		<-sigCh
		log.Ctx(ctx).Info().Msg("Received shutdown signal")
		server.Stop()
		os.Exit(0)
	}()

	log.Ctx(ctx).Info().Msg("Starting SSH server loop")
	return server.Start(ctx)
}

// applyJSONConfig applies JSON configuration to the config struct
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
	if jsonCfg.Shell != "" {
		cfg.Shell = jsonCfg.Shell
	}
}

// applyCLIConfig applies CLI/env configuration to the config struct
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
	if cmd.Shell != "" {
		cfg.Shell = cmd.Shell
	}
}

// defaultShell returns the default shell based on OS
func defaultShell(ctx context.Context) string {
	// Check SHELL env var first
	if shell := os.Getenv("SHELL"); shell != "" {
		log.Ctx(ctx).Info().Str("shell", shell).Msg("Using SHELL environment variable")
		return shell
	}

	switch runtime.GOOS {
	case "windows":
		// On Windows, prefer PowerShell Core (pwsh) over cmd.exe
		// Try to find pwsh in PATH first
		if pwshPath, err := exec.LookPath("pwsh"); err == nil {
			log.Ctx(ctx).Info().Str("shell", pwshPath).Msg("Using PowerShell Core (pwsh)")
			return pwshPath
		}
		// Try PowerShell Windows (powershell)
		if psPath, err := exec.LookPath("powershell"); err == nil {
			log.Ctx(ctx).Info().Str("shell", psPath).Msg("Using Windows PowerShell")
			return psPath
		}
		// Fallback to cmd.exe
		if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
			cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")
			if _, err := os.Stat(cmdPath); err == nil {
				log.Ctx(ctx).Info().Str("shell", cmdPath).Msg("Using Windows cmd.exe (fallback)")
				return cmdPath
			}
		}
		// Last resort
		log.Ctx(ctx).Info().Msg("Using cmd.exe from PATH (last resort)")
		return "cmd.exe"
	default:
		log.Ctx(ctx).Info().Msg("Using default /bin/sh")
		return "/bin/sh"
	}
}

// osSignalToWatch returns the signals to watch based on OS
func osSignalToWatch() []os.Signal {
	switch runtime.GOOS {
	case "windows":
		return []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
	default:
		return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	}
}