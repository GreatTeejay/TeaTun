package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		configPath  = flag.String("config", "", "path to the tunnel TOML config")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("teatun %s  %s/%s  %s\n",
			version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: teatun -config /etc/teatun/<name>.toml")
		os.Exit(2)
	}
	if !fileExists(*configPath) {
		fmt.Fprintf(os.Stderr, "config not found: %s\n", *configPath)
		os.Exit(1)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	setLogLevel(cfg.LogLevel)

	if cfg.GOMAXPROCS > 0 {
		runtime.GOMAXPROCS(cfg.GOMAXPROCS)
	}

	logInfo("teatun %s starting: tunnel=%q mode=%s cpus=%d gomaxprocs=%d",
		version, cfg.TunnelName, cfg.Mode, runtime.NumCPU(), runtime.GOMAXPROCS(0))

	st := newStats()
	shutdownHealth := startHealth(cfg.HealthPort, cfg, st)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := runEngine(ctx, cfg, st)

	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = shutdownHealth(shutCtx)
	cancel()

	if runErr != nil {
		logError("tunnel exited: %v", runErr)
		os.Exit(1)
	}
}
