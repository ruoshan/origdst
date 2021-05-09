package origdst

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestGetOrigDstByFD(t *testing.T) {
	addr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 9999,
	}
	listener, _ := net.ListenTCP("tcp", addr)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		c, _ := net.DialTCP("tcp", nil, addr)
		time.Sleep(1 * time.Second)
		c.Close()
		wg.Done()
	}()
	c, _ := listener.AcceptTCP()
	sc, _ := c.SyscallConn()
	sc.Control(func(fd uintptr) {
		addr2, err := GetOrigalDstByFD(fd)
		if err != nil {
			t.Fatalf("Failed to get origdst: %s", err)
		}
		if addr2.Port != 9999 || !addr2.IP.Equal(addr.IP) {
			t.Fatalf("Expect addr %s, but got %s", addr, addr2)
		}
	})
	wg.Wait()
}
