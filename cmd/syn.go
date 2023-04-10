package cmd

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/richardjennings/ports/pkg/syn"
	"github.com/spf13/cobra"
	"strconv"
	"strings"
	"time"
)

var ports string

var synCmd = &cobra.Command{
	Use:  "syn <ip, ip range or host>",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		prefix, err := ipHostRange(args[0])
		cobra.CheckErr(err)

		ports, err := parsePortSpec(ports)
		cobra.CheckErr(err)

		timeout := setTimeout(len(ports), 1000) + 1*time.Second

		fmt.Printf("Starting Ports at %s\n", time.Now().Format(time.RFC822))

		res, err := syn.Scan(prefix, ports, timeout)
		cobra.CheckErr(err)

		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			res, ok := res.Results[addr]
			if !ok {
				continue
			}
			if !res.Live {
				continue
			}
			fmt.Printf("Ports scan report for (%s)\n", addr)
			fmt.Printf("Host is up (%s latency)\n\n", res.Latency)
			fmt.Printf("PORT    STATE  SERVICE\n")
			var state string
			for _, p := range res.Ports {
				v, ok := res.Result[p]
				if !ok || !v.Open {
					continue
				}
				if v.Open {
					state = "open"
				} else if v.Closed {
					state = "closed"
				}
				fmt.Printf("%-7s %-6s %s\n", strconv.Itoa(int(v.Port)), state, layers.TCPPortNames[v.Port])
			}
			if res.IsLocal {
				vendorPrefix := [3]byte{res.Mac[0], res.Mac[1], res.Mac[2]}
				fmt.Printf("Mac Address: %s (%s)\n", res.Mac, macs.ValidMACPrefixMap[vendorPrefix])
			}
			fmt.Println()
		}
		ipCount := 1 << (32 - prefix.Bits())
		countIpsUp := 0
		for _, v := range res.Results {
			if v.Live {
				countIpsUp++
			}
		}
		fmt.Printf("\nPorts done: %d IP address (%d host up) scanned in %f seconds\n", ipCount, countIpsUp, res.End.Sub(res.Start).Seconds())
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

func parsePortSpec(portSpec string) ([]layers.TCPPort, error) {
	var ports []layers.TCPPort
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
				for i := nn; i <= nnn; i++ {
					ports = append(ports, layers.TCPPort(i))
				}
			}
		} else {
			nn, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, layers.TCPPort(nn))
		}
	}
	return ports, nil
}

func init() {
	synCmd.PersistentFlags().StringVarP(&ports, "ports", "p", "0-1000", "--ports<spec>")
	rootCmd.AddCommand(synCmd)
}
