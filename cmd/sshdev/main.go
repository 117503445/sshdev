package main

import (
	"context"

	"github.com/117503445/goutils/glog"
	"github.com/alecthomas/kong"
	"github.com/rs/zerolog/log"
)

var Ctx context.Context

func init() {
	Ctx = context.Background()
}

func main() {
	// Initialize logger first before any logging
	glog.InitZeroLog()

	ctx := kong.Parse(&cli)

	log.Ctx(Ctx).Info().Interface("cli", cli).Msg("CLI parsed, starting execution")

	if err := ctx.Run(); err != nil {
		log.Ctx(Ctx).Fatal().Err(err).Msg("run failed")
	}
}