package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run relay",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hello!")
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
