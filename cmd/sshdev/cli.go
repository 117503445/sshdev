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
	log.Info().Msg("CmdRun.Run() called, initializing configuration")

	cfg := &sshlib.Config{}

	// First, try to load from JSON config
	if cmd.ConfigJSON != "" {
		log.Info().Msg("Loading configuration from JSON")
		var jsonCfg JSONConfig
		if err := json.Unmarshal([]byte(cmd.ConfigJSON), &jsonCfg); err != nil {
			log.Warn().Err(err).Msg("failed to parse SSHDEV_CONFIG_JSON, ignoring")
		} else {
			applyJSONConfig(cfg, &jsonCfg)
			log.Info().Msg("JSON configuration applied")
		}
	}

	// Then, apply command line / env overrides (these take precedence)
	applyCLIConfig(cfg, cmd)
	log.Info().Msg("CLI configuration applied")

	// Set default shell based on OS if still empty
	if cfg.Shell == "" {
		cfg.Shell = defaultShell()
	}

	log.Info().
		Str("shell", cfg.Shell).
		Str("listenAddr", cfg.ListenAddr).
		Bool("hostKeyBuiltin", cfg.HostKeyBuiltin).
		Str("hostKeyPath", cfg.HostKeyPath).
		Bool("hasHostKeyContent", cfg.HostKeyContent != "").
		Msg("Configuration ready, validating")

	if err := cfg.Validate(); err != nil {
		log.Error().Err(err).Str("shell", cfg.Shell).Msg("Configuration validation failed")
		return err
	}

	log.Info().Msg("Configuration validated successfully")

	log.Info().
		Str("listen", cfg.ListenAddr).
		Bool("passwordAuth", cfg.HasPasswordAuth()).
		Bool("publicKeyAuth", cfg.HasPublicKeyAuth()).
		Str("shell", cfg.Shell).
		Msg("Starting SSH server")

	server, err := sshlib.NewServer(cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create SSH server")
		return err
	}

	log.Info().Msg("SSH server created, setting up signal handler")

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, osSignalToWatch()...)

	go func() {
		<-sigCh
		log.Info().Msg("Received shutdown signal")
		server.Stop()
		os.Exit(0)
	}()

	log.Info().Msg("Starting SSH server loop")
	return server.Start(context.Background())
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
func defaultShell() string {
	// Check SHELL env var first
	if shell := os.Getenv("SHELL"); shell != "" {
		log.Info().Str("shell", shell).Msg("Using SHELL environment variable")
		return shell
	}

	switch runtime.GOOS {
	case "windows":
		// On Windows, prefer PowerShell Core (pwsh) over cmd.exe
		// Try to find pwsh in PATH first
		if pwshPath, err := exec.LookPath("pwsh"); err == nil {
			log.Info().Str("shell", pwshPath).Msg("Using PowerShell Core (pwsh)")
			return pwshPath
		}
		// Try PowerShell Windows (powershell)
		if psPath, err := exec.LookPath("powershell"); err == nil {
			log.Info().Str("shell", psPath).Msg("Using Windows PowerShell")
			return psPath
		}
		// Fallback to cmd.exe
		if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
			cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")
			if _, err := os.Stat(cmdPath); err == nil {
				log.Info().Str("shell", cmdPath).Msg("Using Windows cmd.exe (fallback)")
				return cmdPath
			}
		}
		// Last resort
		log.Info().Msg("Using cmd.exe from PATH (last resort)")
		return "cmd.exe"
	default:
		log.Info().Msg("Using default /bin/sh")
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