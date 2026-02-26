package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/117503445/goutils/glog"
	"github.com/117503445/sshdev/pkg/sshlib"
)

var cli struct {
	Run CmdRun `cmd:"" help:"Run SSH server"`
}

type CmdRun struct {
	ListenAddr     string `name:"listen" help:"listen address" default:"0.0.0.0:2222" env:"SSHD_LISTEN"`
	HostKeyPath    string `name:"host-key" help:"host key file path" default:"./host_key" env:"SSHD_HOST_KEY"`
	AuthMode       string `name:"auth-mode" help:"auth mode (password/publickey/none/all)" default:"password" env:"SSHD_AUTH_MODE"`
	Username       string `name:"username" help:"username for authentication" env:"SSHD_USERNAME"`
	AuthorizedKeys string `name:"authorized-keys" help:"authorized keys file path" env:"SSHD_AUTHORIZED_KEYS"`
	Shell          string `name:"shell" help:"default shell" default:"/bin/bash" env:"SSHD_SHELL"`
	Password       string `name:"password" help:"password for authentication (only from env)" env:"SSHD_PASSWORD"`
}

func (cmd *CmdRun) Run() error {
	glog.InitZeroLog()

	cfg := &sshlib.Config{
		ListenAddr:     cmd.ListenAddr,
		HostKeyPath:    cmd.HostKeyPath,
		AuthMode:       sshlib.ParseAuthMode(cmd.AuthMode),
		Username:       cmd.Username,
		AuthorizedKeys: cmd.AuthorizedKeys,
		Shell:          cmd.Shell,
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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Info().Msg("Received shutdown signal")
		server.Stop()
		os.Exit(0)
	}()

	return server.Start()
}