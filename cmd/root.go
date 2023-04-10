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
	var addr netip.Addr
	var err error
	addr, err = netip.ParseAddr(v)
	if err == nil {
		return addr, nil
	}
	ips, err := net.LookupIP(v)
	if err != nil {
		return addr, errors.New("unable to parse ip or host")
	}
	if len(ips) == 0 {
		return addr, errors.New("could not resolve an A record for host")
	}
	addr, _ = netip.AddrFromSlice(ips[0])
	return addr, nil
}

func ipHostRange(v string) (netip.Prefix, error) {
	var prefix netip.Prefix
	var err error
	prefix, err = netip.ParsePrefix(v)
	if err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(v)
	if err == nil {
		return netip.PrefixFrom(addr, 32), nil
	}
	ips, err := net.LookupIP(v)
	if err != nil {
		return prefix, errors.New("unable to parse ip or host")
	}
	if len(ips) == 0 {
		return prefix, errors.New("could not resolve an A record for host")
	}
	addr, _ = netip.AddrFromSlice(ips[0].To4())
	return netip.PrefixFrom(addr, 32), nil
}
