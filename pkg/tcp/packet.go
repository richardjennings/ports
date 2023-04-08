package tcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
)

type (
	PacketFactory struct {
		buf     gopacket.SerializeBuffer
		srcPort layers.TCPPort
		SYN     bool
	}
	PacketFactoryOption func(p *PacketFactory)
)

func PacketFactoryWithSyn() PacketFactoryOption {
	return func(p *PacketFactory) {
		p.SYN = true
	}
}

func NewPacketFactory(opts ...PacketFactoryOption) *PacketFactory {
	pf := &PacketFactory{
		buf: gopacket.NewSerializeBuffer(),
	}
	for _, opt := range opts {
		opt(pf)
	}
	pf.srcPort = layers.TCPPort(49152 + rand.Intn(61000-49152))
	return pf
}

func (p *PacketFactory) Create(
	src net.IP,
	srcMAC net.HardwareAddr,
	dst net.IP,
	dstMAC net.HardwareAddr,
	dstPort layers.TCPPort,
	srcPort layers.TCPPort,
) (buf []byte, err error) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src,
		DstIP:    dst,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: layers.TCPPort(dstPort),
		//Seq:     seq,
		SYN: p.SYN,
	}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err = tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return
	}
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(p.buf, opt, eth, ip, tcp)
	return p.buf.Bytes(), err
}
