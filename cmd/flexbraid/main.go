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
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/tunnel"
)

// version is the FlexBraid release version. It is injected at build time
// via -ldflags "-X main.version=<v>"; the Makefile is the single source of
// truth for release versions. Unversioned dev builds (plain `go build`)
// report "dev" rather than a stale milestone string.
var version = "dev"

// parseLevel maps the config's log.level string to a slog.Level.
func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// statsSource is anything that can produce a telemetry snapshot (M5.1):
// both the client and the server implement Snapshot().
type statsSource interface{ Snapshot() tunnel.Snapshot }

// serveTelemetry starts the optional HTTP JSON endpoint and periodic
// structured-log snapshot. Both are off by default (telemetry.listen and
// telemetry.interval_sec are empty/zero unless configured).
func serveTelemetry(ctx context.Context, log *slog.Logger, cfg *config.Config, src statsSource) {
	if cfg.Telemetry.IntervalSec > 0 {
		interval := time.Duration(cfg.Telemetry.IntervalSec * float64(time.Second))
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					data, err := json.Marshal(src.Snapshot())
					if err != nil {
						continue
					}
					log.Info("telemetry", "interval", interval.String(), "snapshot", string(data))
				}
			}
		}()
	}
	if cfg.Telemetry.Listen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc(cfg.Telemetry.Path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(src.Snapshot())
		})
		srv := &http.Server{Addr: cfg.Telemetry.Listen, Handler: mux}
		go func() {
			log.Info("telemetry http listening", "addr", cfg.Telemetry.Listen, "path", cfg.Telemetry.Path)
			if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
				log.Error("telemetry http", "error", err)
			}
		}()
	}
}

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Dynamic log level so SIGHUP reload can raise/lower verbosity live.
	slogLevel := new(slog.LevelVar)
	slogLevel.Set(parseLevel(cfg.Log.Level))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel}))

	var run func(context.Context) error
	var start func() error
	var src statsSource
	var c *tunnel.Client
	var s *tunnel.Server
	switch cfg.Mode {
	case config.ModeClient:
		c, err = tunnel.NewClient(cfg, logger)
		if err == nil {
			start = c.Start
			run = c.Run
			src = c
		}
	case config.ModeServer:
		s, err = tunnel.NewServer(cfg, logger)
		if err == nil {
			start = s.Start
			run = s.Run
			src = s
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

	// Optional telemetry (M5.1): HTTP JSON snapshot + periodic log.
	if src != nil {
		serveTelemetry(ctx, logger, cfg, src)
	}

	// SIGHUP reload (M5.2): re-parse the config and apply the live subset.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				nc, loadErr := config.Load(*cfgPath)
				if loadErr != nil {
					logger.Error("reload: config invalid; keeping previous", "error", loadErr)
					continue
				}
				var reloadErr error
				switch {
				case c != nil:
					reloadErr = c.Reload(nc)
				case s != nil:
					reloadErr = s.Reload(nc)
				}
				if reloadErr != nil {
					logger.Error("reload failed; keeping previous settings", "error", reloadErr)
					continue
				}
				// Live knobs: mirror into the process-wide logger + telemetry.
				slogLevel.Set(parseLevel(nc.Log.Level))
				logger.Info("config reloaded",
					"level", nc.Log.Level,
					"fec_mode", nc.FEC.Mode,
					"health_loss_alpha", nc.Health.LossAlphaFast,
					"gap_ms", nc.Delivery.GapTimeoutMS)
			}
		}
	}()

	if err := run(ctx); err != nil {
		logger.Error("tunnel stopped with error", "error", err)
		os.Exit(1)
	}
	logger.Info("tunnel stopped")
}
