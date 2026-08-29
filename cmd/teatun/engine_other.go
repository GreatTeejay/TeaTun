//go:build !linux

package main

import (
	"context"
	"fmt"
	"runtime"
)

// runEngine is Linux-only: it needs TUN devices, raw ICMP sockets and recvmmsg.
// This stub lets the package build and its portable logic be tested on other
// platforms.
func runEngine(_ context.Context, _ *Config, _ *Stats) error {
	return fmt.Errorf("flagtun runs on Linux only (this is %s)", runtime.GOOS)
}
