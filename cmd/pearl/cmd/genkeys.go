package cmd

import (
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/spf13/cobra"
)

// genkeysCmd represents the genkeys command
var genkeysCmd = &cobra.Command{
	Use:   "genkeys",
	Short: "Generate tor relay keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		return genkeys()
	},
}

func init() {
	Register(genkeysCmd.Flags(), relayData)

	rootCmd.AddCommand(genkeysCmd)
}

func genkeys() error {
	k, err := torconfig.GenerateKeys()
	if err != nil {
		return err
	}

	d := relayData.Data()
	return d.SetKeys(k)
}
