package cmd

import (
	"fmt"

	"github.com/mmcloughlin/pearl/meta"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print git revision",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(meta.GitSHAFull)
	},
}

func init() {
	if meta.Populated() {
		rootCmd.AddCommand(versionCmd)
	}
}
