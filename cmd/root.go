package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"log"
	"net"
	"net/netip"
)

var rootCmd = &cobra.Command{
	Use:   "ports",
	Short: "ports is a port scanner",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
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
