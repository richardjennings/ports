package cmd

import (
	"fmt"
	"github.com/richardjennings/ports/pkg/scan/syn"
	"github.com/spf13/cobra"
	"net/netip"
	"strconv"
	"time"
)

var scanCmd = &cobra.Command{
	Use: "scan",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var scanSynCmd = &cobra.Command{
	Use:  "syn <ip> <start port> <end port>",
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		var openOnly bool
		addr, err := netip.ParseAddr(args[0])
		cobra.CheckErr(err)
		frm, err := strconv.ParseUint(args[1], 10, 16)
		cobra.CheckErr(err)
		to, err := strconv.ParseUint(args[2], 10, 16)
		cobra.CheckErr(err)
		timeout := time.Duration((int(to)-int(frm))/800) * time.Second
		fmt.Printf("using timeout %s\n", timeout)
		res, err := syn.Scan(addr, uint16(frm), uint16(to), timeout)
		cobra.CheckErr(err)
		fmt.Printf("syn scan for ip: %s, mac: %s, port range: %d-%d\n", res.IP, res.Mac, res.FromPort, res.ToPort)
		openOnly = true
		for _, v := range res.Result {
			if openOnly {
				if !v.Open {
					continue
				}
			}
			fmt.Println(v)
		}
		fmt.Printf("in %f seconds\n", res.End.Sub(res.Start).Seconds())
		return nil
	},
}

func init() {
	scanCmd.AddCommand(scanSynCmd)
	rootCmd.AddCommand(scanCmd)
}
