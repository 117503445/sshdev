package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"strings"

	"github.com/117503445/goutils/glog"
	"github.com/alecthomas/kong"
	"github.com/rs/zerolog/log"
)

var Ctx context.Context

// Version 在 CI 构建时注入发布版本。
var Version = "dev"

func init() {
	Ctx = context.Background()
}

func main() {
	// Initialize logger first before any logging
	glog.InitZeroLog()
	Ctx = log.Logger.WithContext(context.Background())
	if err := loadEnvironment(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := kong.Parse(&cli)

	if err := ctx.Run(); err != nil {
		log.Ctx(Ctx).Fatal().Err(err).Msg("run failed")
	}
}

// loadEnvironment 在解析 CLI 前加载 args 指定的 .env，使配置参与环境变量解析。
func loadEnvironment(args []string) error {
	path := ".env"
	explicit := false
	for i, arg := range args {
		if arg == "--env-file" {
			if i+1 >= len(args) {
				return fmt.Errorf("--env-file 缺少路径")
			}
			path = args[i+1]
			explicit = true
		}
		if strings.HasPrefix(arg, "--env-file=") {
			path = strings.TrimPrefix(arg, "--env-file=")
			explicit = true
		}
	}
	if explicit {
		return godotenv.Overload(path)
	}
	err := godotenv.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
