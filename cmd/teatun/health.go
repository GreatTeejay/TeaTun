package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// startHealth serves a tiny status endpoint on 127.0.0.1:port. It is bound to
// loopback only: the counters are harmless, but there is no reason to expose
// them to the internet. Returns a shutdown func, or a no-op if port is 0.
func startHealth(port int, cfg *Config, st *Stats) func(context.Context) error {
	if port <= 0 {
		return func(context.Context) error { return nil }
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// Healthy when the peer has been heard from recently, or when nothing
		// has arrived yet within the first grace period after start.
		snap := st.snapshot()
		alive := snap.PeerSeenSecs >= 0 && snap.PeerSeenSecs <= 60
		grace := snap.UptimeSecs < 45
		if alive || grace {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "peer unreachable")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snap := st.snapshot()
		out := struct {
			Tunnel string `json:"tunnel"`
			Mode   string `json:"mode"`
			Peer   string `json:"peer"`
			TunDev string `json:"tun"`
			MTU    int    `json:"mtu"`
			statsSnapshot
		}{
			Tunnel:        cfg.TunnelName,
			Mode:          cfg.Mode,
			Peer:          cfg.RemoteIP,
			TunDev:        cfg.TunName,
			MTU:           cfg.MTU,
			statsSnapshot: snap,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		logWarn("health: cannot listen on 127.0.0.1:%d: %v (continuing without it)", port, err)
		return func(context.Context) error { return nil }
	}
	go func() {
		logInfo("health endpoint on http://127.0.0.1:%d/stats", port)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logWarn("health server stopped: %v", err)
		}
	}()
	return srv.Shutdown
}
