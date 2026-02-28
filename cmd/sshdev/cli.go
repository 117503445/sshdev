package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/117503445/goutils/glog"
	"github.com/117503445/sshdev/pkg/sshlib"
)

var cli struct {
	Run CmdRun `cmd:"" help:"Run SSH server"`
}

type CmdRun struct {
	ListenAddr          string `name:"listen" help:"listen address" default:"0.0.0.0:2222" env:"SSHDEV_LISTEN"`
	HostKeyPath         string `name:"host-key" help:"host key file path" default:"./host_key" env:"SSHDEV_HOST_KEY"`
	AuthMode            string `name:"auth-mode" help:"auth mode (password/publickey/none/all)" default:"password" env:"SSHDEV_AUTH_MODE"`
	Username            string `name:"username" help:"username for authentication" env:"SSHDEV_USERNAME"`
	AuthorizedKeys      string `name:"authorized-keys" help:"authorized keys file path" env:"SSHDEV_AUTHORIZED_KEYS"`
	Shell               string `name:"shell" help:"default shell" env:"SSHDEV_SHELL"`
	Password            string `name:"password" help:"password for authentication (only from env)" env:"SSHDEV_PASSWORD"`
}

func (cmd *CmdRun) Run() error {
	glog.InitZeroLog()

	// Set default shell based on OS
	shell := cmd.Shell
	if shell == "" {
		shell = defaultShell()
	}

	cfg := &sshlib.Config{
		ListenAddr:     cmd.ListenAddr,
		HostKeyPath:    cmd.HostKeyPath,
		AuthMode:       sshlib.ParseAuthMode(cmd.AuthMode),
		Username:       cmd.Username,
		AuthorizedKeys: cmd.AuthorizedKeys,
		Shell:          shell,
		Password:       cmd.Password,
	}

	if cfg.AuthorizedKeys == "" {
		cfg.AuthorizedKeys = sshlib.DefaultAuthorizedKeysPath()
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	server, err := sshlib.NewServer(cfg)
	if err != nil {
		return err
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, osSignalToWatch()...)

	go func() {
		<-sigCh
		log.Info().Msg("Received shutdown signal")
		server.Stop()
		os.Exit(0)
	}()

	return server.Start()
}

// defaultShell returns the default shell based on OS
func defaultShell() string {
	switch runtime.GOOS {
	case "windows":
		return "cmd.exe"
	default:
		return "/bin/bash"
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