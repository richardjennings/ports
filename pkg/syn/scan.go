package syn

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
	"github.com/richardjennings/ports/pkg/arp"
	"github.com/richardjennings/ports/pkg/ping"
	"github.com/richardjennings/ports/pkg/tcp"
	"go.uber.org/ratelimit"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"
)

type (
	Result struct {
		Start   time.Time
		End     time.Time
		Results map[netip.Addr]*ScanResult
	}
	ScanResult struct {
		IP      netip.Addr
		Mac     net.HardwareAddr
		Latency time.Duration
		IsLocal bool
		Ports   []layers.TCPPort
		Result  map[layers.TCPPort]Port
		Live    bool
	}
	ResChanS struct {
		Ip   netip.Addr
		Port Port
	}
	Port struct {
		Port   layers.TCPPort
		Open   bool
		Closed bool
		// filtered results are absent from the results
	}
)

func Scan(prefix netip.Prefix, ports []layers.TCPPort, timeout time.Duration) (Result, error) {
	var err error
	var handle *pcap.Handle

	wDone := make(chan bool)
	rDone := make(chan bool)
	resChan := make(chan ResChanS)

	result := Result{
		Start:   time.Now(),
		Results: make(map[netip.Addr]*ScanResult),
	}

	router, err := netroute.New()
	if err != nil {
		return result, err
	}

	iFace, gw, src, err := router.Route(prefix.Addr().AsSlice())
	if err != nil {
		return result, err
	}

	// live host detection
	macs, err := arp.Scan(prefix, time.Second*3)
	if err != nil {
		if err != nil {
			log.Printf("mac error %s", err)
		}
		return result, err
	}
	if len(macs) < 1 {
		return result, errors.New("arp scan did not return macs")
	}

	// build results for all ips in prefix. Might be inefficient - might be useful ?
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		scan := &ScanResult{}
		scan.IP = addr
		scan.Result = make(map[layers.TCPPort]Port, len(ports))
		scan.Ports = ports
		if gw == nil {
			scan.IsLocal = true
		}
		result.Results[addr] = scan
	}

	// set mac for results as either gateway or local net
	if gw != nil {
		for _, v := range result.Results {
			v.Mac = macs[0].MAC
			// use ping to determine if live
		}
	} else {
		for _, v := range macs {
			result.Results[v.IP].Mac = v.MAC
			// replied to arp so,
			result.Results[v.IP].Live = true
		}
	}

	// perform ping to ascertain latency
	// @todo concurrently
	for addr, r := range result.Results {
		if len(r.Mac) == 0 {
			// local without arp response
			continue
		}
		t, err := ping.Ping(addr, r.Mac)
		if err != nil {
			return result, err
		}
		result.Results[addr].Latency = t
		if t > 0 {
			result.Results[addr].Live = true
		}
	}

	// open live handle
	handle, err = pcap.OpenLive(iFace.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("open live error %s", err)
		return result, err
	}
	defer handle.Close()

	srcPort := randSrcPort()

	// Filter
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		filter(handle, srcPort, prefix, resChan, rDone)
		wg.Done()
	}()

	// Write Requests
	rl := ratelimit.New(1000)
	go func(result *Result, wDone chan bool) {
		pf := tcp.NewPacketFactory(tcp.PacketFactoryWithSyn())
		var bytes []byte
		for addr, r := range result.Results {
			if !r.Live {
				continue
			}
			for _, v := range ports {
				bytes, _ = pf.Create(src, iFace.HardwareAddr, addr.AsSlice(), r.Mac, v, srcPort)
				_ = rl.Take() // ratelimit pause
				if err = handle.WritePacketData(bytes); err != nil {
					log.Printf("write error %s", err)
					return
				}
			}
		}
		wDone <- true
	}(&result, wDone)

	var ctx context.Context
	var cancel context.CancelFunc

	<-wDone
	// wait for write to finish before starting timeout
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var incomplete bool
	for {
		select {
		case <-ctx.Done():
			result.End = time.Now()
			rDone <- true
			wg.Wait()
			return result, nil
		case r := <-resChan:
			result.Results[r.Ip].Result[r.Port.Port] = r.Port
			// check if all finished
			incomplete = false
			for _, v := range result.Results {
				if len(v.Result) != len(ports) {
					incomplete = true
				}
			}
			if !incomplete {
				cancel()
			}
		}
	}
}

// Filter writes Results to result channel that match characteristics
func filter(handle *pcap.Handle, srcPort layers.TCPPort, prefix netip.Prefix, resChan chan ResChanS, rDone chan bool) {
	var packet gopacket.Packet
	//var err error
	var decoded []gopacket.LayerType
	var srcAddr netip.Addr
	var ok bool
	raw := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ethL := &layers.Ethernet{}
	ip4L := &layers.IPv4{}
	tcpL := &layers.TCP{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, ethL, ip4L, tcpL)
	for {
		select {
		case <-rDone:
			return
		case packet = <-raw.Packets():
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}
			srcAddr, ok = netip.AddrFromSlice(ip4L.SrcIP)
			if tcpL.DstPort == srcPort && ok && prefix.Contains(srcAddr) {
				resChan <- ResChanS{Ip: srcAddr, Port: Port{
					Port:   tcpL.SrcPort,
					Open:   tcpL.SYN && !tcpL.RST,
					Closed: !tcpL.SYN && tcpL.ACK && tcpL.RST,
				}}
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
	case p.Closed:
		return o + "closed"
	default:
		return o + "filtered"
	}

}
