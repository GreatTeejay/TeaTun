package main

import "encoding/binary"

// ---------------------------------------------------------------------------
// wire format
//
// Each inner IPv4 packet from the TUN device is carried inside one ICMP echo
// message:
//
//	ICMP header (8 bytes)
//	  [0]     type      8 (echo request) from the client, 0 (echo reply) from
//	                    the server, so on the wire it looks like an ordinary
//	                    ping/pong exchange
//	  [1]     code      0
//	  [2:4]   checksum  one's-complement over the whole ICMP message (RFC 1071)
//	  [4:6]   id        icmp_id, identical on both ends
//	  [6:8]   seq       a per-sender counter, cosmetic
//	tunnel prefix (4 bytes)
//	  [0]     magic     0x54 ('T')
//	  [1:3]   id        icmp_id again, so a stray echo carrying our id in the
//	                    ICMP header but not in the body is still rejected
//	  [3]     tag       direction (1 = client->server, 2 = server->client)
//	                    optionally OR'd with 0x10 for a keepalive
//	inner
//	  the raw IPv4 packet, or empty for a keepalive
//
// The direction tag is what makes the tunnel correct regardless of how the
// hosts treat ping. When the client sends an echo *request* and the server has
// not blocked ping, the server's kernel answers it automatically, reflecting
// the exact body — direction tag included — back to the client. That reflected
// copy carries the client's own direction (1); the client only accepts the
// peer's direction (2), so it is dropped. The old design filtered on ICMP type
// alone, and since the reflection arrives as an echo reply (the very type the
// client waits for) it was indistinguishable from real return traffic.
// ---------------------------------------------------------------------------

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8

	icmpHdrLen   = 8
	tunPrefixLen = 4
	frameHdrLen  = icmpHdrLen + tunPrefixLen // 12

	prefixMagic = 0x54 // 'T'

	dirClientToServer = 1
	dirServerToClient = 2
	tagKeepalive      = 0x10 // OR'd onto the direction for a keepalive
)

// direction returns the tag this end stamps on outgoing packets and the tag it
// requires on incoming ones.
func directions(isClient bool) (send, recv byte) {
	if isClient {
		return dirClientToServer, dirServerToClient
	}
	return dirServerToClient, dirClientToServer
}

// writeFrameHeader writes the 12-byte ICMP+tunnel header into dst (which must
// have room) for a packet of the given ICMP type, id, sequence and tag. The
// checksum is left zero; fill it with finishFrame once the body is in place.
func writeFrameHeader(dst []byte, icmpType byte, id uint16, seq uint16, tag byte) {
	dst[0] = icmpType
	dst[1] = 0
	dst[2] = 0
	dst[3] = 0
	binary.BigEndian.PutUint16(dst[4:6], id)
	binary.BigEndian.PutUint16(dst[6:8], seq)
	dst[8] = prefixMagic
	binary.BigEndian.PutUint16(dst[9:11], id)
	dst[11] = tag
}

// finishFrame computes and stores the ICMP checksum over the complete message.
func finishFrame(msg []byte) {
	binary.BigEndian.PutUint16(msg[2:4], icmpChecksum(msg))
}

// parseInner validates a received ICMP message and returns the inner IPv4
// payload. ok is false for anything that is not our traffic; keepalive is true
// when the packet is a valid tunnel keepalive carrying no inner data.
//
// wantRecvTag is the direction tag the peer stamps (from directions()). id is
// the tunnel's icmp_id.
func parseInner(msg []byte, id uint16, wantRecvTag byte) (inner []byte, keepalive, ok bool) {
	if len(msg) < frameHdrLen {
		return nil, false, false
	}
	// Accept either echo type; the direction tag, not the type, tells our
	// traffic from a reflection.
	if msg[0] != icmpEchoReply && msg[0] != icmpEchoRequest {
		return nil, false, false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != id {
		return nil, false, false
	}
	if msg[8] != prefixMagic || binary.BigEndian.Uint16(msg[9:11]) != id {
		return nil, false, false
	}
	tag := msg[11]
	if tag&^tagKeepalive != wantRecvTag {
		return nil, false, false
	}
	if tag&tagKeepalive != 0 {
		return nil, true, true
	}
	inner = msg[frameHdrLen:]
	if len(inner) < 20 || inner[0]>>4 != 4 {
		// A data packet with no valid IPv4 inside is noise, not a keepalive.
		return nil, false, false
	}
	return inner, false, true
}

// icmpChecksum is the standard one's-complement sum from RFC 1071.
func icmpChecksum(b []byte) uint16 {
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
	return ^uint16(sum)
}

// stripIP removes a leading IPv4 header if the kernel handed us one. Raw ICMP
// sockets include it on some paths and not others, so look rather than assume.
func stripIP(b []byte) []byte {
	if len(b) >= 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if ihl >= 20 && ihl <= len(b) {
			return b[ihl:]
		}
	}
	return b
}
