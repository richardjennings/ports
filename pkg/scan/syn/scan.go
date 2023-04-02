package syn

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
	"github.com/richardjennings/ports/pkg/arp"
	"github.com/richardjennings/ports/pkg/scan/tcp"
	"go.uber.org/ratelimit"
	"io"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"time"
)

type (
	ScanResult struct {
		IP       netip.Addr
		Mac      net.HardwareAddr
		FromPort uint16
		ToPort   uint16
		Start    time.Time
		End      time.Time
		Result   []Port
	}
	Port struct {
		Port     layers.TCPPort
		Open     bool
		Filtered bool
	}
)

func Scan(addr netip.Addr, start uint16, end uint16, timeout time.Duration) (*ScanResult, error) {
	var err error
	var handle *pcap.Handle
	resChan := make(chan Port)
	scan := &ScanResult{}
	scan.IP = addr
	scan.FromPort = start
	scan.ToPort = end
	numPorts := int(end) - int(start) + 1
	scan.Result = make([]Port, numPorts, numPorts)
	for p := start; p <= end; p++ {
		scan.Result[end-p] = Port{
			Port:     layers.TCPPort(p),
			Open:     false,
			Filtered: false,
		}
	}
	router, err := netroute.New()
	if err != nil {
		return nil, err
	}
	iFace, gw, src, err := router.Route(addr.AsSlice())
	if err != nil {
		return nil, err
	}
	handle, err = pcap.OpenLive(iFace.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("open live error %s", err)
		return nil, err
	}
	defer handle.Close()
	_ = gw

	// This should be a method Mac()...
	macs, err := arp.Scan(netip.PrefixFrom(addr, 32), time.Second*1)
	if err != nil {
		if err != nil {
			log.Printf("mac error %s", err)
		}
		return nil, err
	}
	if len(macs) != 1 {
		return nil, fmt.Errorf("did not get expected mac request response")
	}
	scan.Mac = macs[0].MAC
	scan.Start = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	srcPort := randSrcPort()

	// Filter
	go func() {
		_ = filter(handle, srcPort, resChan, ctx)
	}()

	// Write Requests
	rl := ratelimit.New(1000)
	go func() {
		pf := tcp.NewPacketFactory(tcp.PacketFactoryWithSyn())
		var bytes []byte
		for i := start; i <= end; i++ {
			bytes, _ = pf.Create(src, iFace.HardwareAddr, addr.AsSlice(), scan.Mac, i, srcPort)
			_ = rl.Take()
			if err = handle.WritePacketData(bytes); err != nil {
				log.Printf("write error %s", err)
				return
			}
		}
	}()

	c := 0
	for {
		select {
		case <-ctx.Done():
			scan.End = time.Now()
			return scan, nil
		case r := <-resChan:
			scan.Result[int(r.Port)-int(scan.FromPort)] = r
			if c == int(scan.ToPort)-int(scan.FromPort) {
				scan.End = time.Now()
				cancel()
				log.Printf("hrre")
			}
			c++
		}
	}
}

// Filter writes Results to result channel that match characteristics
func filter(handle *pcap.Handle, srcPort layers.TCPPort, resChan chan Port, ctx context.Context) error {
	var packet gopacket.Packet
	var err error
	var decoded []gopacket.LayerType
	raw := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ethL := &layers.Ethernet{}
	ip4L := &layers.IPv4{}
	tcpL := &layers.TCP{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, ethL, ip4L, tcpL)
	var i int
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		packet, err = raw.NextPacket()
		if err == io.EOF {
			return nil
		} else if err != nil {
			log.Printf("read error %s\n", err)
			continue
		}
		i++
		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			continue
		}
		if tcpL.DstPort == srcPort {
			resChan <- Port{
				Port:     tcpL.SrcPort,
				Open:     tcpL.SYN,
				Filtered: !tcpL.SYN && tcpL.RST,
			}
		}
	}
}

// macOS lower bound and linux upper bound
// do not think we need to actually request a legit ephemeral src Port
// as we want the os to close the connection automatically for us
// e.g. on macOS
// $ sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last
// net.inet.ip.portrange.first: 49152
// net.inet.ip.portrange.last: 65535
func randSrcPort() layers.TCPPort {
	return layers.TCPPort(49152 + rand.Intn(61000-49152))
}

func (p Port) String() string {
	o := fmt.Sprintf("%s ", p.Port)
	switch true {
	case p.Open:
		return o + "open"
	case p.Filtered:
		return o + "filtered"
	default:
		return o + "closed"
	}
}
