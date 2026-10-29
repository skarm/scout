package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/skarm/scout/internal/commands/devcli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := devcli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	stop()
	os.Exit(code)
}
