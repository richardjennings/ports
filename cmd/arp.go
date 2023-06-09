package cmd

import (
	"fmt"
	"github.com/richardjennings/ports/pkg/arp"
	"github.com/spf13/cobra"
	"time"
)

var arpReqCmd = &cobra.Command{
	Use:  "arp <cidr>",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pre, err := ipHostRange(args[0])
		if err != nil {
			return err
		}
		res, err := arp.Scan(pre, time.Second*3)
		cobra.CheckErr(err)
		for _, v := range res {
			fmt.Println(v)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(arpReqCmd)
}
