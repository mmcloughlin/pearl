package cmd

import (
	"github.com/mmcloughlin/pearl"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/spf13/cobra"
)

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Initiate a connection with a relay",
	RunE: func(cmd *cobra.Command, args []string) error {
		return connect()
	},
}
var (
	addr string
)

func init() {
	connectCmd.Flags().StringVarP(&nickname, "nickname", "n", "client", "nickname")
	connectCmd.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1:5000", "address to connect to")

	rootCmd.AddCommand(connectCmd)
}

func connect() error {
	platform := torconfig.NewPlatformHostOS("Tor", "0.2.9.9")
	config := &torconfig.Config{
		Nickname: nickname,
		ORPort:   0,
		Platform: platform.String(),
	}

	logger := log.NewDebug()

	r, err := pearl.NewRouter(config, logger)
	if err != nil {
		log.Err(logger, err, "failed to build router")
		return err
	}

	_, err = r.Connect(addr)
	if err != nil {
		log.Err(logger, err, "failed to connect")
		return err
	}

	return nil
}
