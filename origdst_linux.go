package origdst

import (
	"net"
	"syscall"
	"unsafe"
)

const SOL_IP = 0
const SO_ORIGINAL_DST = 80

// On Linux, the vallen's type is C.socklen_t which is uint32
func getsockopt(fd, level, name uintptr, val unsafe.Pointer, vallen uint32) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		level,
		name,
		uintptr(val),
		uintptr(unsafe.Pointer(&vallen)),
		0,
	)
	if errno != 0 {
		return errno
	}

	return nil
}

// sockaddrPtr returns the Pointer and underlining size of the RawSockaddrInet4 (struct sockaddr_in in C),
// the return values are supposed to be used by getsockopt
func sockaddrPtr(sa *syscall.RawSockaddrInet4) (ptr unsafe.Pointer, size uint32) {
	return unsafe.Pointer(sa), syscall.SizeofSockaddrInet4
}

// GetOrigalDstByFD returns the original TCP destination(ipv4) that's NATed by netfilter using the REDIRECT rule
// in iptables. For more info about SO_ORIGINAL_DST option, please visit:
// https://elixir.bootlin.com/linux/latest/source/net/netfilter/nf_conntrack_proto.c#L239
func GetOrigalDstByFD(fd uintptr) (*net.TCPAddr, error) {
	sa := new(syscall.RawSockaddrInet4)
	saPtr, saLen := sockaddrPtr(sa)
	if err := getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, saPtr, saLen); err != nil {
		return nil, err
	}

	// convert big-endian port(uint16) to little-endian
	h, l := uint8(sa.Port>>8), uint8(sa.Port&0xFF)
	port := uint16(l)<<8 | uint16(h)

	return &net.TCPAddr{
		IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
		Port: int(port),
	}, nil
}

// GetOrginalDst returns the original TCP destination(ipv4) that's NATed by netfilter using the REDIRECT rule
// in iptables. For more info about SO_ORIGINAL_DST option, please visit:
// https://elixir.bootlin.com/linux/latest/source/net/netfilter/nf_conntrack_proto.c#L239
func GetOriginalDst(c *net.TCPConn) (addr *net.TCPAddr, err error) {
	sc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	sc.Control(func(fd uintptr) {
		addr, err = GetOrigalDstByFD(fd)
	})
	return
}
