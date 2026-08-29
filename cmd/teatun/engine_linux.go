//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	keepaliveInterval = 15 * time.Second
	maxTunQueues      = 16
	errBackoff        = 20 * time.Millisecond
)

type engine struct {
	cfg  *Config
	st   *Stats
	pc   net.PacketConn
	p4   *ipv4.PacketConn
	peer *net.IPAddr

	queues []*os.File

	id       uint16
	sendType byte
	sendTag  byte
	recvTag  byte

	seq       uint32
	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

// runEngine builds the tunnel, runs it until ctx is cancelled, then tears it
// down. It blocks for the lifetime of the tunnel.
func runEngine(ctx context.Context, cfg *Config, st *Stats) error {
	e, err := newEngine(cfg, st)
	if err != nil {
		return err
	}
	e.start()
	logInfo("tunnel %q up: %s  peer=%s  tun=%s mtu=%d  icmp_id=%d  queues=%d batch=%d",
		cfg.TunnelName, cfg.Mode, cfg.RemoteIP, cfg.TunName, cfg.MTU, cfg.ICMPID,
		len(e.queues), cfg.RecvBatchSize)

	<-ctx.Done()
	logInfo("shutting down tunnel %q...", cfg.TunnelName)
	e.Close()
	e.wg.Wait()
	logInfo("tunnel %q stopped", cfg.TunnelName)
	return nil
}

func newEngine(cfg *Config, st *Stats) (*engine, error) {
	sendTag, recvTag := directions(cfg.isClient())
	e := &engine{
		cfg:      cfg,
		st:       st,
		peer:     &net.IPAddr{IP: cfg.remoteIPAddr},
		id:       uint16(cfg.ICMPID),
		sendType: byte(cfg.ICMPSendType),
		sendTag:  sendTag,
		recvTag:  recvTag,
		done:     make(chan struct{}),
	}

	if err := e.openRawSocket(); err != nil {
		return nil, err
	}
	if err := e.openTun(); err != nil {
		e.pc.Close()
		return nil, err
	}
	if err := e.configureTun(); err != nil {
		e.closeFDs()
		return nil, err
	}
	return e, nil
}

// openRawSocket opens the shared raw ICMP socket, applies the tuning knobs and
// attaches the kernel filter.
func (e *engine) openRawSocket() error {
	bind := e.cfg.LocalIP
	if bind == "" {
		bind = "0.0.0.0"
	}
	pc, err := net.ListenPacket("ip4:icmp", bind)
	if err != nil {
		return fmt.Errorf("raw ICMP socket on %s: %w (needs CAP_NET_RAW / root)", bind, err)
	}
	e.pc = pc
	e.p4 = ipv4.NewPacketConn(pc)

	e.applyRawSockopts()
	if err := e.attachFilter(); err != nil {
		logDebug("icmp: kernel filter not attached (%v); sorting every echo in Go", err)
	}
	return nil
}

func (e *engine) applyRawSockopts() {
	sc, ok := e.pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		f := int(fd)
		if b := e.cfg.SockBufBytes; b > 0 {
			// FORCE variants need CAP_NET_ADMIN (the unit grants it) and bypass
			// the rmem_max/wmem_max ceilings; fall back to the plain option.
			if unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, b) != nil {
				_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_RCVBUF, b)
			}
			if unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, b) != nil {
				_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_SNDBUF, b)
			}
		}
		if p := e.cfg.SoPriority; p > 0 {
			_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_PRIORITY, p)
		}
		if bp := e.cfg.BusyPollUs; bp > 0 {
			_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_BUSY_POLL, bp)
		}
		if d := e.cfg.DSCP; d > 0 {
			_ = unix.SetsockoptInt(f, unix.IPPROTO_IP, unix.IP_TOS, d<<2)
		}
	})
}

// attachFilter installs a classic BPF program so the kernel drops every echo
// that is not carrying our identifier before it is ever queued to userspace.
// Best effort: everything it filters is re-checked in Go.
func (e *engine) attachFilter() error {
	sc, ok := e.pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("socket has no raw handle")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	// The packet begins at the IP header, so the ICMP fields are addressed
	// relative to the IHL the packet declares (BPF_MSH), never a fixed 20.
	prog := []unix.SockFilter{
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0}, // X = IP header length
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, K: 0},  // A = ICMP type
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: icmpEchoReply},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 3, K: icmpEchoRequest},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 4}, // A = ICMP identifier
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: uint32(e.id)},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	fprog := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	var serr error
	err = rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
	})
	// prog must outlive the syscall.
	runtime.KeepAlive(prog)
	if err != nil {
		return err
	}
	return serr
}

// openTun attaches the TUN queues. A device with more than one queue lets
// several readers pull egress packets in parallel.
func (e *engine) openTun() error {
	q := e.cfg.Workers
	if q < 1 {
		q = 1
	}
	if q > maxTunQueues {
		q = maxTunQueues
	}
	multiqueue := q > 1
	for i := 0; i < q; i++ {
		f, err := openTUN(e.cfg.TunName, multiqueue)
		if err != nil {
			for _, o := range e.queues {
				o.Close()
			}
			e.queues = nil
			return fmt.Errorf("open tun queue %d: %w", i, err)
		}
		e.queues = append(e.queues, f)
	}
	return nil
}

// configureTun brings the interface up and gives it its address, MTU and
// queueing discipline. The address assignment and link-up are required; the
// rest are best effort so a missing `tc` or an odd qdisc name does not stop
// the tunnel.
func (e *engine) configureTun() error {
	dev := e.cfg.TunName
	run := func(critical bool, args ...string) error {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			msg := fmt.Sprintf("%s: %v", join(args), err)
			if len(out) > 0 {
				msg += ": " + trimOutput(out)
			}
			if critical {
				return errors.New(msg)
			}
			logWarn("tun setup (non-fatal): %s", msg)
		}
		return nil
	}

	if err := run(true, "ip", "link", "set", "dev", dev, "up"); err != nil {
		return err
	}
	if err := run(true, "ip", "addr", "replace", e.cfg.LocalTun, "dev", dev); err != nil {
		return err
	}
	_ = run(false, "ip", "link", "set", "dev", dev, "mtu", itoa(e.cfg.MTU))
	if e.cfg.TxQueueLen > 0 {
		_ = run(false, "ip", "link", "set", "dev", dev, "txqueuelen", itoa(e.cfg.TxQueueLen))
	}
	if q := e.cfg.TunQdisc; q != "" && q != "noqueue" {
		_ = run(false, "tc", "qdisc", "replace", "dev", dev, "root", q)
	}
	// Ensure the peer's tunnel address routes over the device even when it is
	// outside the local subnet.
	if e.cfg.peerTunIP != nil && (e.cfg.localTunNet == nil || !e.cfg.localTunNet.Contains(e.cfg.peerTunIP)) {
		_ = run(false, "ip", "route", "replace", e.cfg.peerTunIP.String()+"/32", "dev", dev)
	}
	return nil
}

func (e *engine) start() {
	interval := time.Duration(e.cfg.StatsIntervalSecs) * time.Second

	for i, q := range e.queues {
		e.wg.Add(2)
		go e.egressWorker(i, q)
		go e.ingressWorker(i, q)
	}
	e.wg.Add(1)
	go e.keepaliveLoop()
	if interval > 0 {
		e.wg.Add(1)
		go e.statsLoop(interval)
	}
}

// egressWorker reads inner packets from one TUN queue, wraps each in an ICMP
// echo and writes it to the peer.
func (e *engine) egressWorker(idx int, tun *os.File) {
	defer e.wg.Done()
	frame := make([]byte, frameHdrLen+e.cfg.MTU+64)
	body := frame[frameHdrLen:]
	fails := 0
	for {
		n, err := tun.Read(body)
		if err != nil {
			if e.stopping() {
				return
			}
			fails++
			e.st.onTxError()
			if fails == 1 || fails%1000 == 0 {
				logWarn("egress[%d]: tun read failed (%d times): %v", idx, fails, err)
			}
			time.Sleep(errBackoff)
			continue
		}
		fails = 0
		if n <= 0 {
			continue
		}
		if body[0]>>4 != 4 {
			// Only IPv4 is carried; the device is addressed with IPv4 only.
			continue
		}
		seq := uint16(atomic.AddUint32(&e.seq, 1))
		writeFrameHeader(frame[:frameHdrLen], e.sendType, e.id, seq, e.sendTag)
		msg := frame[:frameHdrLen+n]
		finishFrame(msg)
		if _, err := e.pc.WriteTo(msg, e.peer); err != nil {
			if e.stopping() {
				return
			}
			e.st.onTxError()
			continue
		}
		e.st.onTxData(n)
	}
}

// ingressWorker drains the shared raw socket with recvmmsg and writes the
// decapsulated inner packets to its TUN queue.
func (e *engine) ingressWorker(idx int, tun *os.File) {
	defer e.wg.Done()

	batch := e.cfg.RecvBatchSize
	if batch < 1 {
		batch = 1
	}
	bufCap := frameHdrLen + e.cfg.MTU + 128
	if bufCap < 2048 {
		bufCap = 2048
	}

	msgs := make([]ipv4.Message, batch)
	bufs := make([][]byte, batch)
	for i := range msgs {
		bufs[i] = make([]byte, bufCap)
		msgs[i].Buffers = [][]byte{bufs[i]}
	}

	delivered := false
	fails := 0
	for {
		n, err := e.p4.ReadBatch(msgs, 0)
		for i := 0; i < n; i++ {
			if msgs[i].N > 0 {
				delivered = true
				e.handleInbound(bufs[i][:msgs[i].N], tun)
			}
		}
		if err == nil {
			fails = 0
			continue
		}
		if e.stopping() {
			return
		}
		if !delivered {
			// recvmmsg may be unavailable on some kernels/socket types; after a
			// few failures with nothing ever received, use the plain reader.
			fails++
			if fails >= 3 {
				logWarn("ingress[%d]: batched receive not working (%v); using plain reader", idx, err)
				e.ingressSingle(idx, tun, bufCap)
				return
			}
		}
		e.st.onRxError()
		time.Sleep(errBackoff)
	}
}

func (e *engine) ingressSingle(idx int, tun *os.File, bufCap int) {
	buf := make([]byte, bufCap)
	fails := 0
	for {
		n, _, err := e.pc.ReadFrom(buf)
		if err != nil {
			if e.stopping() {
				return
			}
			fails++
			e.st.onRxError()
			if fails == 1 || fails%1000 == 0 {
				logWarn("ingress[%d]: read failed (%d times): %v", idx, fails, err)
			}
			time.Sleep(errBackoff)
			continue
		}
		fails = 0
		e.handleInbound(buf[:n], tun)
	}
}

func (e *engine) handleInbound(pkt []byte, tun *os.File) {
	msg := stripIP(pkt)
	inner, keep, ok := parseInner(msg, e.id, e.recvTag)
	if !ok {
		e.st.onDropInvalid()
		return
	}
	if keep {
		e.st.onRxKeepalive()
		return
	}
	if _, err := tun.Write(inner); err != nil {
		if e.stopping() {
			return
		}
		e.st.onRxError()
		return
	}
	e.st.onRxData(len(inner))
}

func (e *engine) keepaliveLoop() {
	defer e.wg.Done()
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	buf := make([]byte, frameHdrLen)
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			seq := uint16(atomic.AddUint32(&e.seq, 1))
			writeFrameHeader(buf, e.sendType, e.id, seq, e.sendTag|tagKeepalive)
			finishFrame(buf)
			if _, err := e.pc.WriteTo(buf, e.peer); err != nil {
				if e.stopping() {
					return
				}
				e.st.onTxError()
				continue
			}
			e.st.onTxKeepalive()
		}
	}
}

func (e *engine) statsLoop(interval time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	last := e.st.snapshot()
	lastTime := time.Now()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			snap := e.st.snapshot()
			dt := time.Since(lastTime).Seconds()
			if dt <= 0 {
				dt = 1
			}
			txRate := float64(snap.TxBytes-last.TxBytes) * 8 / dt
			rxRate := float64(snap.RxBytes-last.RxBytes) * 8 / dt
			seen := "never"
			if snap.PeerSeenSecs >= 0 {
				seen = fmt.Sprintf("%ds ago", snap.PeerSeenSecs)
			}
			logInfo("stats  tx=%s rx=%s | tx=%d rx=%d pkt  drop=%d err=%d/%d  peer=%s",
				humanRate(txRate), humanRate(rxRate),
				snap.TxPackets, snap.RxPackets,
				snap.DropInvalid, snap.TxErrors, snap.RxErrors, seen)
			last = snap
			lastTime = time.Now()
		}
	}
}

func (e *engine) stopping() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (e *engine) Close() {
	e.closeOnce.Do(func() {
		close(e.done)
		e.closeFDs()
	})
}

func (e *engine) closeFDs() {
	if e.pc != nil {
		_ = e.pc.Close()
	}
	for _, q := range e.queues {
		_ = q.Close()
	}
}

// ---- small local helpers (kept here to avoid a util dependency on exec) ----

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func join(a []string) string {
	s := ""
	for i, v := range a {
		if i > 0 {
			s += " "
		}
		s += v
	}
	return s
}

func trimOutput(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		s = s[:200]
	}
	// collapse newlines for a single-line log
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			out = append(out, ' ')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
