package cmd

import (
	"github.com/spf13/cobra"
)

var synScanCmd = &cobra.Command{
	Use: "scan <cidr>",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	rootCmd.AddCommand(synScanCmd)
}
