// +build linux

package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/ruoshan/origdst"
)

func sigHandler(f func()) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	<-c
	f()
}

func main() {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:9999")
	l, _ := net.ListenTCP("tcp", addr)
	go SigHandler(func() {
		l.Close()
	})

	for {
		c, err := l.AcceptTCP()
		if err != nil {
			return
		}
		go func(c *net.TCPConn) {
			a, err := origdst.GetOriginalDst(c)
			if err != nil {
				log.Printf("Failed with %s", err)
				return
			}
			log.Printf("Original destination: %s", a)
			c.Close()
		}(c)
	}
}
