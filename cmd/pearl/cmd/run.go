package cmd

import (
	"fmt"

	"github.com/mmcloughlin/pearl"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run relay",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}
var (
	nickname string
	port     int
)

func init() {
	runCmd.Flags().StringVarP(&nickname, "nickname", "n", "pearl", "nickname")
	runCmd.Flags().IntVarP(&port, "port", "p", 9111, "relay port")

	rootCmd.AddCommand(runCmd)
}

func run() error {
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

	desc := r.Descriptor()
	doc, err := desc.Document()
	if err != nil {
		return err
	}

	fmt.Println(string(doc.Encode()))

	go func() {
		r.Serve()
	}()

	authority := "127.0.0.1:7000"
	err = desc.PublishToAuthority(authority)
	if err != nil {
		return err
	}
	logger.With("authority", authority).Info("published descriptor")

	select {}
}
