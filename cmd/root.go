package cmd

import (
	"github.com/spf13/cobra"
	"log"
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
