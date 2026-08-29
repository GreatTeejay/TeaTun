package main

import (
	"sync/atomic"
	"time"
)

// Stats holds the live counters. Everything is atomic so the health endpoint
// and the stats logger can read while the data path writes.
type Stats struct {
	startedUnix int64

	txPackets uint64 // TUN -> ICMP (egress), data only
	txBytes   uint64
	rxPackets uint64 // ICMP -> TUN (ingress), data only
	rxBytes   uint64

	txKeepalive uint64
	rxKeepalive uint64

	dropInvalid uint64 // received ICMP that was not ours / malformed
	txErrors    uint64
	rxErrors    uint64

	lastRxUnixNano int64 // last time any valid peer packet arrived
}

func newStats() *Stats {
	return &Stats{startedUnix: time.Now().Unix()}
}

func (s *Stats) onTxData(n int) {
	atomic.AddUint64(&s.txPackets, 1)
	atomic.AddUint64(&s.txBytes, uint64(n))
}
func (s *Stats) onRxData(n int) {
	atomic.AddUint64(&s.rxPackets, 1)
	atomic.AddUint64(&s.rxBytes, uint64(n))
	atomic.StoreInt64(&s.lastRxUnixNano, time.Now().UnixNano())
}
func (s *Stats) onRxKeepalive() {
	atomic.AddUint64(&s.rxKeepalive, 1)
	atomic.StoreInt64(&s.lastRxUnixNano, time.Now().UnixNano())
}
func (s *Stats) onTxKeepalive() { atomic.AddUint64(&s.txKeepalive, 1) }
func (s *Stats) onDropInvalid() { atomic.AddUint64(&s.dropInvalid, 1) }
func (s *Stats) onTxError()     { atomic.AddUint64(&s.txErrors, 1) }
func (s *Stats) onRxError()     { atomic.AddUint64(&s.rxErrors, 1) }

// peerLastSeen returns how long ago a valid peer packet last arrived, or -1 if
// none ever has.
func (s *Stats) peerLastSeen() time.Duration {
	ns := atomic.LoadInt64(&s.lastRxUnixNano)
	if ns == 0 {
		return -1
	}
	return time.Since(time.Unix(0, ns))
}

type statsSnapshot struct {
	UptimeSecs   int64  `json:"uptime_secs"`
	TxPackets    uint64 `json:"tx_packets"`
	TxBytes      uint64 `json:"tx_bytes"`
	RxPackets    uint64 `json:"rx_packets"`
	RxBytes      uint64 `json:"rx_bytes"`
	TxKeepalive  uint64 `json:"tx_keepalive"`
	RxKeepalive  uint64 `json:"rx_keepalive"`
	DropInvalid  uint64 `json:"drop_invalid"`
	TxErrors     uint64 `json:"tx_errors"`
	RxErrors     uint64 `json:"rx_errors"`
	PeerSeenSecs int64  `json:"peer_last_seen_secs"` // -1 = never
}

func (s *Stats) snapshot() statsSnapshot {
	seen := int64(-1)
	if d := s.peerLastSeen(); d >= 0 {
		seen = int64(d.Seconds())
	}
	return statsSnapshot{
		UptimeSecs:   time.Now().Unix() - atomic.LoadInt64(&s.startedUnix),
		TxPackets:    atomic.LoadUint64(&s.txPackets),
		TxBytes:      atomic.LoadUint64(&s.txBytes),
		RxPackets:    atomic.LoadUint64(&s.rxPackets),
		RxBytes:      atomic.LoadUint64(&s.rxBytes),
		TxKeepalive:  atomic.LoadUint64(&s.txKeepalive),
		RxKeepalive:  atomic.LoadUint64(&s.rxKeepalive),
		DropInvalid:  atomic.LoadUint64(&s.dropInvalid),
		TxErrors:     atomic.LoadUint64(&s.txErrors),
		RxErrors:     atomic.LoadUint64(&s.rxErrors),
		PeerSeenSecs: seen,
	}
}
