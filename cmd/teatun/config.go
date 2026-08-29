package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the on-disk tunnel description. The field tags match the TOML keys
// the manager script writes, so a config produced by icmptun.sh loads as-is.
type Config struct {
	TunnelName string `toml:"tunnel_name"`
	Mode       string `toml:"mode"` // "server" (iran) or "client" (kharej)
	LocalIP    string `toml:"local_ip"`
	RemoteIP   string `toml:"remote_ip"`

	LocalTun string `toml:"local_tun"` // e.g. 155.155.1.1/24
	PeerTun  string `toml:"peer_tun"`  // e.g. 155.155.1.2/24
	TunName  string `toml:"tun_name"`
	MTU      int    `toml:"mtu"`
	TunQdisc string `toml:"tun_qdisc"`

	HealthPort int    `toml:"health_port"`
	Transport  string `toml:"transport"`

	LogLevel          string `toml:"log_level"`
	StatsIntervalSecs int    `toml:"stats_interval_secs"`

	GOMAXPROCS         int `toml:"gomaxprocs"`
	Workers            int `toml:"workers"`
	TunWriteQueueDepth int `toml:"tun_write_queue_depth"`
	TunWriteWorkers    int `toml:"tun_write_workers"`
	TxQueueLen         int `toml:"tx_queue_len"`

	ICMPID       int `toml:"icmp_id"`
	ICMPSendType int `toml:"icmp_send_type"`
	ICMPRecvType int `toml:"icmp_recv_type"`
	SockBufBytes int `toml:"sock_buf_bytes"`

	BusyPollUs    int `toml:"busy_poll_us"`
	DSCP          int `toml:"dscp"`
	SoPriority    int `toml:"so_priority"`
	RecvBatchSize int `toml:"recv_batch_size"`

	// Filled in by normalize(), not read from disk.
	localTunIP   net.IP
	localTunNet  *net.IPNet
	peerTunIP    net.IP
	remoteIPAddr net.IP
}

const (
	modeServer = "server"
	modeClient = "client"
)

// LoadConfig reads, decodes and validates a tunnel config file.
func LoadConfig(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		// Unknown keys are a warning, not an error: a newer manager may add
		// knobs an older binary does not know, and the tunnel should still run.
		keys := make([]string, 0, len(u))
		for _, k := range u {
			keys = append(keys, k.String())
		}
		logWarn("config has %d unknown key(s), ignored: %s", len(keys), strings.Join(keys, ", "))
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return &c, nil
}

// normalize validates required fields and fills defaults for everything the
// manager may leave at zero.
func (c *Config) normalize() error {
	switch c.Mode {
	case modeServer, modeClient:
	case "":
		return fmt.Errorf("mode is required (server|client)")
	default:
		return fmt.Errorf("mode %q is invalid (server|client)", c.Mode)
	}

	if c.Transport == "" {
		c.Transport = "icmp"
	}
	if c.Transport != "icmp" {
		return fmt.Errorf("transport %q is unsupported (only icmp)", c.Transport)
	}

	if c.RemoteIP == "" {
		return fmt.Errorf("remote_ip is required")
	}
	if ip := parseHostIPv4(c.RemoteIP); ip != nil {
		c.remoteIPAddr = ip
	} else {
		return fmt.Errorf("remote_ip %q is not a resolvable IPv4 address", c.RemoteIP)
	}

	if c.LocalTun == "" {
		return fmt.Errorf("local_tun is required (e.g. 155.155.1.1/24)")
	}
	ip, ipnet, err := net.ParseCIDR(c.LocalTun)
	if err != nil {
		return fmt.Errorf("local_tun %q: %w", c.LocalTun, err)
	}
	c.localTunIP = ip.To4()
	c.localTunNet = ipnet
	if c.localTunIP == nil {
		return fmt.Errorf("local_tun %q must be IPv4", c.LocalTun)
	}

	if c.PeerTun != "" {
		pip, _, err := net.ParseCIDR(c.PeerTun)
		if err != nil {
			// Allow a bare address without a mask for peer_tun.
			if p := net.ParseIP(c.PeerTun); p != nil {
				pip = p
			} else {
				return fmt.Errorf("peer_tun %q: %w", c.PeerTun, err)
			}
		}
		c.peerTunIP = pip.To4()
	}

	if c.TunName == "" {
		c.TunName = "tun0"
	}
	if len(c.TunName) >= 16 {
		return fmt.Errorf("tun_name %q is too long (max 15)", c.TunName)
	}

	if c.MTU == 0 {
		c.MTU = 1320
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("mtu %d out of range (576-9000)", c.MTU)
	}

	if c.TunQdisc == "" {
		c.TunQdisc = "fq"
	}

	if c.ICMPID == 0 {
		c.ICMPID = 2001
	}
	if c.ICMPID < 1 || c.ICMPID > 65535 {
		return fmt.Errorf("icmp_id %d out of range (1-65535)", c.ICMPID)
	}

	// icmp_send_type / icmp_recv_type follow the mode when unset. The client
	// side pings (echo request, 8) and the server answers (echo reply, 0).
	if c.ICMPSendType == 0 && c.ICMPRecvType == 0 {
		if c.Mode == modeClient {
			c.ICMPSendType, c.ICMPRecvType = icmpEchoRequest, icmpEchoReply
		} else {
			c.ICMPSendType, c.ICMPRecvType = icmpEchoReply, icmpEchoRequest
		}
	}
	if c.ICMPSendType != icmpEchoRequest && c.ICMPSendType != icmpEchoReply {
		return fmt.Errorf("icmp_send_type %d must be 0 or 8", c.ICMPSendType)
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.StatsIntervalSecs == 0 {
		c.StatsIntervalSecs = 30
	}

	cores := runtime.NumCPU()
	if c.Workers <= 0 {
		c.Workers = cores
	}
	if c.Workers > 64 {
		c.Workers = 64
	}
	if c.RecvBatchSize <= 0 {
		c.RecvBatchSize = 256
	}
	if c.RecvBatchSize > 4096 {
		c.RecvBatchSize = 4096
	}

	if c.DSCP < 0 || c.DSCP > 63 {
		return fmt.Errorf("dscp %d out of range (0-63)", c.DSCP)
	}
	if c.SoPriority < 0 || c.SoPriority > 7 {
		return fmt.Errorf("so_priority %d out of range (0-7)", c.SoPriority)
	}
	if c.BusyPollUs < 0 || c.BusyPollUs > 10000 {
		return fmt.Errorf("busy_poll_us %d out of range (0-10000)", c.BusyPollUs)
	}

	if c.HealthPort < 0 || c.HealthPort > 65535 {
		return fmt.Errorf("health_port %d out of range (0-65535)", c.HealthPort)
	}

	if c.TunnelName == "" {
		c.TunnelName = c.TunName
	}
	return nil
}

// isClient reports whether this end dials (kharej side).
func (c *Config) isClient() bool { return c.Mode == modeClient }

// parseHostIPv4 accepts a literal IPv4 address or resolves a hostname to its
// first IPv4 address.
func parseHostIPv4(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// fileExists is a small helper used by main for clearer error messages.
func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
