package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

func main() {
	path := flag.String("config", "", "absolute path to native Kubernetes runtime JSON configuration")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	config, err := k8s.ReadRuntimeConfig(*path)
	if err != nil {
		logger.Error("native connector configuration rejected", "error", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := k8s.Run(ctx, config, logger); err != nil {
		logger.Error("native connector stopped", "error", err)
		os.Exit(1)
	}
}
