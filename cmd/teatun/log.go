package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Leveled logging to stderr. systemd/journald captures stderr, so no file
// handling is needed here. The level is a single atomic int so it can be read
// on the hot path without a lock.
const (
	lvlDebug = iota
	lvlInfo
	lvlWarn
	lvlError
)

var logLevel int32 = lvlInfo

func setLogLevel(name string) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		atomic.StoreInt32(&logLevel, lvlDebug)
	case "warn", "warning":
		atomic.StoreInt32(&logLevel, lvlWarn)
	case "error":
		atomic.StoreInt32(&logLevel, lvlError)
	default:
		atomic.StoreInt32(&logLevel, lvlInfo)
	}
}

func logAt(level int32, tag, format string, args ...interface{}) {
	if atomic.LoadInt32(&logLevel) > level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s %s\n", time.Now().Format("2006-01-02 15:04:05"), tag, msg)
}

func logDebug(f string, a ...interface{}) { logAt(lvlDebug, "DBG", f, a...) }
func logInfo(f string, a ...interface{})  { logAt(lvlInfo, "INF", f, a...) }
func logWarn(f string, a ...interface{})  { logAt(lvlWarn, "WRN", f, a...) }
func logError(f string, a ...interface{}) { logAt(lvlError, "ERR", f, a...) }
