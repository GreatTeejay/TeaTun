//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// TUN flags and the TUNSETIFF ioctl, copied from <linux/if_tun.h> so no cgo or
// third-party package is needed.
const (
	iffTUN         = 0x0001
	iffNoPI        = 0x1000
	iffMultiQueue  = 0x0100
	ioctlTUNSETIFF = 0x400454ca
)

type ifReq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// openTUN attaches one queue to the named interface, creating it on first use.
// With multiqueue set, calling it again for the same name adds another queue,
// so several goroutines can read the device without contending for a lock.
func openTUN(name string, multiqueue bool) (*os.File, error) {
	if len(name) >= 16 {
		return nil, fmt.Errorf("interface name %q is too long", name)
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("/dev/net/tun: %v (is the tun module loaded?)", err)
	}
	var req ifReq
	copy(req.name[:], name)
	req.flags = iffTUN | iffNoPI
	if multiqueue {
		req.flags |= iffMultiQueue
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(ioctlTUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %v", name, errno)
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
