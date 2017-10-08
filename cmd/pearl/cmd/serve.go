package cmd

import (
	"github.com/mmcloughlin/pearl"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/spf13/cobra"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a relay server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return serve()
	},
}
var (
	nickname string
	port     int
)

func init() {
	serveCmd.Flags().StringVarP(&nickname, "nickname", "n", "pearl", "nickname")
	serveCmd.Flags().IntVarP(&port, "port", "p", 9111, "relay port")

	rootCmd.AddCommand(serveCmd)
}

func serve() error {
	platform := torconfig.NewPlatformHostOS("Tor", "0.2.9.9")
	config := &torconfig.Config{
		Nickname: nickname,
		ORPort:   uint16(port),
		Platform: platform.String(),
	}

	logger := log.NewDebug()

	r, err := pearl.NewRouter(config, logger)
	if err != nil {
		return err
	}

	go func() {
		r.Serve()
	}()

	authority := "127.0.0.1:7000"
	desc := r.Descriptor()
	err = desc.PublishToAuthority(authority)
	if err != nil {
		return err
	}
	logger.With("authority", authority).Info("published descriptor")

	select {}
}
