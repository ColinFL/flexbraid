// Command flexbraid runs the FlexBraid multi-WAN bonding tunnel.
//
// FlexBraid weaves several WANs into one logical link so that an inner VPN
// such as WireGuard sees a single stable connection. This entry point loads
// the YAML config, validates it, and starts the tunnel pipeline.
//
// Stage: M0 (foundation). Config parsing + validation are wired up; the data
// path (transport, FEC, scheduler, health) lands in later milestones.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ColinFL/flexbraid/internal/config"
)

func main() {
	var (
		configPath = flag.String("c", "", "path to YAML config file (required)")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("flexbraid 0.0.1 (M0 foundation)")
		return
	}
	if *configPath == "" {
		log.Fatalf("usage: flexbraid -c config.yaml")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("flexbraid: %v", err)
	}
}

func run(cfg *config.Config) error {
	logger := log.New(os.Stderr, "[flexbraid] ", log.LstdFlags)
	logger.Printf("loaded config: mode=%s listen=%s session=%s scheduler=%s balance_by=%s",
		cfg.Mode, cfg.Listen, cfg.SessionID, cfg.Scheduler.Mode, cfg.Scheduler.BalanceBy)
	logger.Printf("fec: enabled=%v mode=%s max_loss_pct=%.0f",
		cfg.FEC.Enabled, cfg.FEC.Mode, cfg.FEC.MaxLossPct)
	for _, w := range cfg.WANs {
		fec := "global"
		if w.FECMaxLossPct != nil {
			fec = fmt.Sprintf("%.0f%%", *w.FECMaxLossPct)
		}
		logger.Printf("wan: id=%s transport=%s iface=%q capacity=%dMbps weight=%.1f fec=%s",
			w.ID, w.Transport, w.Iface, w.CapacityMbps, w.Weight, fec)
	}

	// TODO(M1): start the tunnel pipeline (session, framing, crypto, UDP transport).
	logger.Printf("foundation build — data path not yet implemented (see docs/DESIGN.md roadmap)")
	return nil
}
