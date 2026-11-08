package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/authority"
)

type secureConfig struct {
	Bootstrap       authority.Bootstrap `json:"bootstrap"`
	ExportDirectory string              `json:"export_directory"`
}

func runSecure(arguments []string) error {
	flags := flag.NewFlagSet("secure", flag.ContinueOnError)
	configPath := flags.String("config", "", "private independent Authority configuration")
	initialize := flags.Bool("initialize", false, "operator-only database initialization")
	listen := flags.String("listen", "127.0.0.1:8446", "signed loopback gateway listener")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *configPath == "" || flags.NArg() != 0 {
		return errors.New("secure Authority requires --config")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	var config secureConfig
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.ExportDirectory == "" || config.Bootstrap.Validate() != nil {
		return errors.New("invalid Authority configuration")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn := os.Getenv("RATCHET_AUTHORITY_DSN")
	if *initialize {
		dsn = os.Getenv("RATCHET_AUTHORITY_MIGRATION_DSN")
	}
	if dsn == "" {
		return errors.New("separate Authority database credentials required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return errors.New("invalid Authority database configuration")
	}
	defer pool.Close()
	if *initialize {
		return authority.Initialize(ctx, pool, config.Bootstrap)
	}
	service, err := authority.Open(ctx, pool)
	if err != nil {
		return err
	}
	configured, _ := json.Marshal(config.Bootstrap)
	persisted, _ := json.Marshal(service.Bootstrap)
	if string(configured) != string(persisted) {
		return errors.New("Authority bootstrap configuration changed")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("Authority gateway must bind a loopback IP")
	}
	// Every request authenticates its core gateway and action proof. Public file
	// export is retried independently from committed SQL; core verifies root/quorum.
	handler := service.Handler()
	server := &http.Server{Addr: *listen, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) })}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServe() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			stop, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			return server.Shutdown(stop)
		case err := <-finished:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			export, done := context.WithTimeout(ctx, 5*time.Second)
			err := service.ExportFiles(export, config.ExportDirectory)
			done()
			if err != nil && ctx.Err() == nil {
				_, _ = os.Stderr.WriteString("Authority public export pending; core retains only verified policy\n")
			}
		}
	}
}
