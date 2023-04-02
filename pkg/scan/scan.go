package scan

import (
	"context"
	"github.com/google/gopacket/pcap"
	"net"
)

type (
	Filter  func(handle *pcap.Handle, ctx context.Context, result chan Result)
	Request interface {
		Write() error
	}
	Result interface {
		IsOpen() bool
		IsClosed() bool
		Port() uint32
		Ip() net.IP
	}
)
