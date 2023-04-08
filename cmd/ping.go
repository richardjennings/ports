package cmd

import (
	"fmt"
	"github.com/richardjennings/ports/pkg/arp"
	"github.com/richardjennings/ports/pkg/ping"
	"github.com/spf13/cobra"
	"net/netip"
	"time"
)

var pingReqCmd = &cobra.Command{
	Use:  "ping <addr>",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := netip.MustParseAddr(args[0])
		res, err := arp.Scan(netip.PrefixFrom(addr, 32), time.Second)
		cobra.CheckErr(err)
		r, err := ping.Ping(addr, res[0].MAC)
		cobra.CheckErr(err)
		fmt.Println(r)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pingReqCmd)
}
