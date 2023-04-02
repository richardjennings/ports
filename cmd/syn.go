package cmd

import (
	"errors"
	"fmt"
	"github.com/richardjennings/ports/pkg/scan/syn"
	"github.com/spf13/cobra"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var ports string

var synCmd = &cobra.Command{
	Use:  "syn <ip or host>",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		addr, err := ipHost(args[0])

		ports, err := parsePortSpec(ports)
		cobra.CheckErr(err)

		timeout := setTimeout(len(ports), 1000)
		fmt.Printf("using timeout %s\n", timeout)

		res, err := syn.Scan(addr, ports, timeout)
		cobra.CheckErr(err)
		fmt.Printf("syn scan for ip: %s, mac: %s \n", res.IP, res.Mac)
		for _, v := range res.Result {
			if !v.Open {
				continue
			}
			fmt.Println(v)
		}
		fmt.Printf("in %f seconds\n", res.End.Sub(res.Start).Seconds())
		return nil
	},
}

func setTimeout(numPorts int, ratelimit int) time.Duration {
	duration := int(float32(numPorts) / (float32(ratelimit) * 0.8))
	if duration < 1 {
		duration = 1
	}
	return time.Duration(duration) * time.Second
}

func parsePortSpec(portSpec string) ([]uint16, error) {
	ports := []uint16{}
	if portSpec == "" {
		return []uint16{22}, nil
	}
	pParts := strings.Split(portSpec, ",")
	for _, v := range pParts {
		if strings.Contains(v, "-") {
			// try to create range
			rParts := strings.Split(v, "-")
			if len(rParts) == 2 {
				nn, err := strconv.ParseUint(rParts[0], 10, 16)
				if err != nil {
					return nil, err
				}
				nnn, err := strconv.ParseUint(rParts[1], 10, 16)
				if err != nil {
					return nil, err
				}
				for i := nn; i < nnn; i++ {
					ports = append(ports, uint16(i))
				}
			}
		} else {
			nn, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, uint16(nn))
		}
	}
	return ports, nil
}

func ipHost(v string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(v)
	if err != nil {
		ips, err := net.LookupIP(v)
		if err != nil {
			return netip.Addr{}, errors.New("unable to parse ip or host")
		}
		if len(ips) == 0 {
			return netip.Addr{}, errors.New("could not resolve an A record for host")
		}
		addr, _ = netip.AddrFromSlice(ips[0])
	}
	return addr, nil
}

func init() {
	synCmd.PersistentFlags().StringVarP(&ports, "ports", "p", "0-1000", "--ports<spec>")
	rootCmd.AddCommand(synCmd)
}