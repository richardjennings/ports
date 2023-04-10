package arp

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
	"io"
	"log"
	"net"
	"net/netip"
	"time"
)

type (
	Result struct {
		IP     netip.Addr
		MAC    net.HardwareAddr
		Vendor string
	}
)

// Scan creates ARP requests for the given range or gateway
func Scan(prefix netip.Prefix, timeout time.Duration) ([]Result, error) {
	var handle *pcap.Handle

	router, err := netroute.New()
	if err != nil {
		return nil, err
	}

	iFace, gw, src, err := router.Route(prefix.Addr().AsSlice())
	if err != nil {
		return nil, err
	}

	handle, err = pcap.OpenLive(iFace.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result := make(chan *layers.ARP, 10)

	dstPrefix := prefix
	if gw != nil {
		addr, _ := netip.AddrFromSlice(gw.To4())
		dstPrefix = netip.PrefixFrom(addr, 32)
	}
	go readArpResponses(handle, result, dstPrefix, ctx)

	if gw == nil {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if err := writeArpRequest(handle, iFace, src, addr.AsSlice()); err != nil {
				return nil, err
			}
		}
	} else {
		if err := writeArpRequest(handle, iFace, src, gw); err != nil {
			return nil, err
		}
	}

	var results []Result
	var addr netip.Addr

	prefixLength := 1 << (32 - prefix.Bits())

	for {
		select {
		case <-ctx.Done():
			return results, nil
		case r := <-result:
			mac := r.SourceHwAddress
			vendorPrefix := [3]byte{mac[0], mac[1], mac[2]}
			addr, _ = netip.AddrFromSlice(r.SourceProtAddress)
			results = append(
				results,
				Result{
					IP:     addr,
					MAC:    mac,
					Vendor: macs.ValidMACPrefixMap[vendorPrefix],
				},
			)

			if len(results) >= prefixLength {
				cancel()
			}
		}
	}

}

func readArpResponses(handle *pcap.Handle, result chan *layers.ARP, prefix netip.Prefix, ctx context.Context) {
	raw := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	var packet gopacket.Packet
	var err error
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
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp := arpLayer.(*layers.ARP)
		if arp.Operation != layers.ARPReply {
			continue
		}
		addr, _ := netip.AddrFromSlice(arp.SourceProtAddress)
		if prefix.Contains(addr) {
			result <- arp
		}
	}
}

// send arp request
func writeArpRequest(handle *pcap.Handle, iface *net.Interface, src net.IP, dst net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(src.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dst.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func (r Result) String() string {
	return fmt.Sprintf("%-15s %s %s", r.IP, r.MAC, r.Vendor)
}
