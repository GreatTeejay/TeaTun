package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildFrame mirrors what egressWorker/keepaliveLoop put on the wire, so the
// tests exercise the exact bytes the peer will parse.
func buildFrame(icmpType byte, id, seq uint16, tag byte, inner []byte) []byte {
	msg := make([]byte, frameHdrLen+len(inner))
	writeFrameHeader(msg[:frameHdrLen], icmpType, id, seq, tag)
	copy(msg[frameHdrLen:], inner)
	finishFrame(msg)
	return msg
}

func sampleIPv4() []byte {
	p := make([]byte, 40)
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], 40)
	return p
}

func TestDataRoundTrip(t *testing.T) {
	const id = uint16(4242)
	inner := sampleIPv4()

	// client -> server
	sendTag, recvTag := directions(true) // client's tags
	frame := buildFrame(icmpEchoRequest, id, 1, sendTag, inner)

	// server parses it: server accepts the client's direction.
	_, srvRecv := directions(false)
	if srvRecv != sendTag {
		t.Fatalf("server should expect the client's send tag")
	}
	got, keep, ok := parseInner(frame, id, srvRecv)
	if !ok || keep {
		t.Fatalf("server rejected valid data frame: ok=%v keep=%v", ok, keep)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("inner mismatch")
	}
	_ = recvTag
}

// TestReflectionRejected is the core correctness guarantee: a client's own echo
// request, reflected verbatim by the peer's kernel as an echo reply, must not be
// accepted by the client as inbound data.
func TestReflectionRejected(t *testing.T) {
	const id = uint16(2001)
	inner := sampleIPv4()

	sendTag, recvTag := directions(true) // client
	frame := buildFrame(icmpEchoRequest, id, 7, sendTag, inner)

	// The kernel echoes the request body back unchanged as an echo reply. The
	// client sees an echo reply (its recv type) carrying its own send tag.
	reflected := make([]byte, len(frame))
	copy(reflected, frame)
	reflected[0] = icmpEchoReply // kernel turns request into reply
	finishFrame(reflected)

	_, _, ok := parseInner(reflected, id, recvTag)
	if ok {
		t.Fatalf("client accepted a reflected copy of its own packet")
	}
}

func TestKeepalive(t *testing.T) {
	const id = uint16(1234)
	sendTag, _ := directions(false) // server sends
	frame := buildFrame(icmpEchoReply, id, 3, sendTag|tagKeepalive, nil)

	_, clientRecv := directions(true)
	inner, keep, ok := parseInner(frame, id, clientRecv)
	if !ok || !keep {
		t.Fatalf("keepalive not recognised: ok=%v keep=%v", ok, keep)
	}
	if inner != nil {
		t.Fatalf("keepalive should have no inner payload")
	}
}

func TestWrongIDRejected(t *testing.T) {
	inner := sampleIPv4()
	sendTag, _ := directions(true)
	frame := buildFrame(icmpEchoRequest, 100, 1, sendTag, inner)

	_, srvRecv := directions(false)
	if _, _, ok := parseInner(frame, 200, srvRecv); ok {
		t.Fatalf("frame with the wrong id was accepted")
	}
}

func TestChecksumValid(t *testing.T) {
	inner := sampleIPv4()
	sendTag, _ := directions(true)
	frame := buildFrame(icmpEchoRequest, 555, 9, sendTag, inner)
	// A correct ICMP checksum makes the one's-complement sum of the whole
	// message zero (0xffff).
	if s := rawSum(frame); s != 0xffff {
		t.Fatalf("checksum invalid: sum=%#x", s)
	}
}

func TestStripIP(t *testing.T) {
	inner := sampleIPv4()
	sendTag, _ := directions(true)
	msg := buildFrame(icmpEchoRequest, 7, 1, sendTag, inner)

	// Prepend a 20-byte IPv4 header as the kernel sometimes does.
	withIP := make([]byte, 20+len(msg))
	withIP[0] = 0x45
	copy(withIP[20:], msg)

	if got := stripIP(withIP); !bytes.Equal(got, msg) {
		t.Fatalf("stripIP did not remove the IP header")
	}
	if got := stripIP(msg); !bytes.Equal(got, msg) {
		t.Fatalf("stripIP altered a header-less message")
	}
}

func rawSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum & 0xffff
}
