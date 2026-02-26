package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
)

var Ctx context.Context

func init() {
	Ctx = context.Background()
}

func main() {
	ctx := kong.Parse(&cli)
	log := zerolog.Ctx(Ctx)

	log.Info().Interface("cli", cli).Send()

	if err := ctx.Run(); err != nil {
		log.Fatal().Err(err).Msg("run failed")
	}
}