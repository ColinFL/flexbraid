package tunnel

// Runtime reload (M5.2). A SIGHUP re-parses the config file and applies the
// live-adjustable subset without restarting the tunnel. Structural changes
// (transports, listeners, crypto keys, WAN topology, FEC mode, scheduler
// mode) are rejected with ErrReloadRequiresRestart — the process keeps
// running with its previous settings; apply those by restarting.

import (
	"errors"
	"fmt"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

// ErrReloadRequiresRestart wraps changes that cannot be applied to a running
// tunnel (they would rebind sockets or renegotiate crypto).
var ErrReloadRequiresRestart = errors.New("reload: change requires restart")

// clientReloadable reports whether nc differs from st only in fields the
// client can adjust live. The FEC *settings* are adjustable; the FEC mode
// (crosspath vs per-WAN) is structural because it changes the codec wiring.
func clientReloadable(st, nc *config.Config) error {
	if nc.Listen != st.Listen ||
		nc.Server != st.Server ||
		nc.WGPeer != st.WGPeer ||
		nc.SessionID != st.SessionID ||
		nc.MTU != st.MTU ||
		nc.Transport != st.Transport ||
		nc.Crypto.Key != st.Crypto.Key ||
		nc.Crypto.Cipher != st.Crypto.Cipher ||
		nc.FEC.Mode != st.FEC.Mode ||
		nc.Scheduler.Mode != st.Scheduler.Mode ||
		nc.Scheduler.Affinity != st.Scheduler.Affinity ||
		nc.Scheduler.BalanceBy != st.Scheduler.BalanceBy ||
		len(nc.WANs) != len(st.WANs) {
		return fmt.Errorf("structural change: %w", ErrReloadRequiresRestart)
	}
	for i := range st.WANs {
		a, b := &st.WANs[i], &nc.WANs[i]
		if a.ID != b.ID ||
			a.Transport != b.Transport ||
			a.Iface != b.Iface ||
			a.LocalIP != b.LocalIP ||
			a.FIB != b.FIB {
			return fmt.Errorf("wan topology change: %w", ErrReloadRequiresRestart)
		}
	}
	return nil
}

// Reload applies a reloadable configuration to the running client:
// scheduler capacities/weights, delivery gap+bound, and health tuning all
// take effect immediately. It returns ErrReloadRequiresRestart for
// structural changes (see clientReloadable).
func (c *Client) Reload(nc *config.Config) error {
	if err := clientReloadable(c.cfg, nc); err != nil {
		return err
	}
	for i, wan := range c.wans {
		if i >= len(nc.WANs) {
			continue
		}
		// Live: scheduler weight for this WAN.
		c.sched.AddPath(wan.id, float64(nc.WANs[i].CapacityMbps))
		// Live: health thresholds/weights. FEC is unchanged (mode is
		// structural), so the compensable-loss floor stays valid.
		params, err := fecParamsFor(c.cfg, &nc.WANs[i])
		if err != nil {
			return err
		}
		wan.health.Reload(healthOptions(nc.Health, monitorMaxLoss(params), c.probeInterval))
	}
	c.delivery.Reload(
		time.Duration(nc.Delivery.GapTimeoutMS)*time.Millisecond,
		nc.Delivery.MaxPending,
	)
	return nil
}

// Reload applies the server's live-adjustable subset: health tuning on the
// already-registered path monitors (per session). Structural changes and the
// capacity cap (read per-frame, not worth a cfg lock for a trust-bound
// constant) require a restart.
func (s *Server) Reload(nc *config.Config) error {
	if nc.Listen != s.cfg.Listen ||
		nc.WGPeer != s.cfg.WGPeer ||
		nc.SessionID != s.cfg.SessionID ||
		nc.Transport != s.cfg.Transport ||
		nc.MTU != s.cfg.MTU ||
		nc.FEC.Mode != s.cfg.FEC.Mode ||
		nc.Crypto.Key != s.cfg.Crypto.Key ||
		nc.Crypto.Cipher != s.cfg.Crypto.Cipher ||
		nc.Scheduler.Mode != s.cfg.Scheduler.Mode ||
		nc.Scheduler.BalanceBy != s.cfg.Scheduler.BalanceBy {
		return fmt.Errorf("structural change: %w", ErrReloadRequiresRestart)
	}
	if nc.Scheduler.CapacityCapMbps != s.cfg.Scheduler.CapacityCapMbps {
		return fmt.Errorf("capacity_cap change: %w", ErrReloadRequiresRestart)
	}
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	for _, st := range s.states {
		for _, ps := range st.paths {
			ps.health.Reload(healthOptions(nc.Health, monitorMaxLoss(s.fecParams), 0))
		}
	}
	return nil
}
