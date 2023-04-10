package ping

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
	"io"
	"log"
	"net"
	"net/netip"
	"time"
)

func Ping(addr netip.Addr, mac net.HardwareAddr) (time.Duration, error) {

	router, err := netroute.New()
	if err != nil {
		return 0, err
	}
	iFace, gw, src, err := router.Route(addr.AsSlice())
	_ = gw

	eth := &layers.Ethernet{
		SrcMAC:       iFace.HardwareAddr,
		DstMAC:       mac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    src,
		DstIP:    addr.AsSlice(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		TOS:      20,
		Id:       7780,
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Checksum: 0,
		Id:       0,
		Seq:      0,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, eth, ip, icmp); err != nil {
		return 0, err
	}

	handle, err := pcap.OpenLive(iFace.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return 0, err
	}
	defer handle.Close()

	// listen for responses
	raw := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
	defer cancel()
	res := make(chan time.Time)

	go func(ctx context.Context, res chan time.Time, addr netip.Addr) {
		var packet gopacket.Packet
		var decoded []gopacket.LayerType
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			packet, err = raw.NextPacket()
			if err == io.EOF {
				return
			} else if err != nil {
				log.Printf("read error %s\n", err)
				continue
			}
			ethL := &layers.Ethernet{}
			ip4L := &layers.IPv4{}
			icmpL := &layers.ICMPv4{}
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, ethL, ip4L, icmpL)
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}
			if ip4L.SrcIP.Equal(addr.AsSlice()) {
				res <- time.Now()
			}
		}
	}(ctx, res, addr)

	// send packet
	s := time.Now()
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return 0, err
	}

	select {
	case <-ctx.Done():
		return -1, nil
	case r := <-res:
		t := r.Sub(s)
		cancel()
		return t, nil
	}
}
