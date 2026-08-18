// Command flexbraid runs the FlexBraid multi-WAN bonding tunnel.
//
// FlexBraid weaves several WANs into one logical link so that an inner VPN
// such as WireGuard sees a single stable connection. This milestone (M2)
// implements the single-WAN data path with end-to-end FEC; the M3 scheduler
// adds multi-WAN load balancing and the health monitor.
//
// Usage:
//
//	flexbraid -c config.yaml
//	flexbraid -version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/tunnel"
)

var version = "0.1.0-m4"

func main() {
	cfgPath := flag.String("c", "config.yaml", "path to YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("flexbraid %s\n", version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flexbraid: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var run func(context.Context) error
	var start func() error
	switch cfg.Mode {
	case config.ModeClient:
		var c *tunnel.Client
		c, err = tunnel.NewClient(cfg, logger)
		if err == nil {
			start = c.Start
			run = c.Run
		}
	case config.ModeServer:
		var s *tunnel.Server
		s, err = tunnel.NewServer(cfg, logger)
		if err == nil {
			start = s.Start
			run = s.Run
		}
	default:
		err = fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "flexbraid: %v\n", err)
		os.Exit(1)
	}
	// Start binds sockets synchronously so init errors (busy port, bad
	// address) surface before any goroutine is spawned.
	if err := start(); err != nil {
		fmt.Fprintf(os.Stderr, "flexbraid: %v\n", err)
		os.Exit(1)
	}

	if err := run(ctx); err != nil {
		logger.Error("tunnel stopped with error", "error", err)
		os.Exit(1)
	}
	logger.Info("tunnel stopped")
}
