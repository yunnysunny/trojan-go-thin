package transport

import (
	"net"

	"github.com/p4gefau1t/trojan-go-thin/tunnel"
)

type Conn struct {
	net.Conn
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return nil
}
