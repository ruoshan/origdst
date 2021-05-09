# Wrapper for getsockopt with SO_ORIGNAL_DST
Use this pkg to retrieve the original destination address after the packets
are REDIERCTed by an iptables rule.

Usage:
```
import "github.com/ruoshan/origdst

func demo() {
    addr, err := origdst.GetOriginalDst(c)
    ...
}
```

directory `demo` is a simple TCP server that print the original destination addr, try
```
# in terminal window A
iptable -t nat -A OUTPUT -p tcp --dport 8888 -j REDIRECT --to-port 9999
cd demo
go run .

# in terminal window B
telnet 127.0.0.1 8888
# you should see the msg in window A
```