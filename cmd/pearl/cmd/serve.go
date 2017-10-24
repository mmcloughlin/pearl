package cmd

import (
	"io"
	"os"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/mmcloughlin/pearl"
	"github.com/mmcloughlin/pearl/check"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/meta"
	"github.com/mmcloughlin/pearl/telemetry"
	"github.com/mmcloughlin/pearl/telemetry/expvar"
	"github.com/mmcloughlin/pearl/telemetry/logging"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/spf13/cobra"
	"github.com/uber-go/tally"
	"github.com/uber-go/tally/multi"
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
	nickname      string
	port          int
	logfile       string
	telemetryAddr string
)

func init() {
	serveCmd.Flags().StringVarP(&nickname, "nickname", "n", "pearl", "nickname")
	serveCmd.Flags().IntVarP(&port, "port", "p", 9111, "relay port")
	serveCmd.Flags().StringVarP(&logfile, "logfile", "l", "pearl.json", "log file")
	serveCmd.Flags().StringVarP(&telemetryAddr, "telemetry", "t", "localhost:7142", "telemetry address")

	Register(serveCmd.Flags(), relayData, authorities)

	rootCmd.AddCommand(serveCmd)
}

func logger(logfile string) (log.Logger, error) {
	base := log15.New()
	fh, err := log15.FileHandler(logfile, log15.JsonFormat())
	if err != nil {
		return nil, err
	}
	base.SetHandler(log15.MultiHandler(
		log15.LvlFilterHandler(log15.LvlInfo,
			log15.StreamHandler(os.Stdout, log15.TerminalFormat()),
		),
		fh,
	))
	return log.NewLog15(base), nil
}

func metrics(l log.Logger) (tally.Scope, io.Closer) {
	return tally.NewRootScope(tally.ScopeOptions{
		Prefix: "pearl",
		Tags:   map[string]string{},
		CachedReporter: multi.NewMultiCachedReporter(
			expvar.NewReporter(),
			logging.NewReporter(l),
		),
	}, 1*time.Second)
}

func serve() error {
	config := &torconfig.Config{
		Nickname: nickname,
		ORPort:   uint16(port),
		Platform: meta.Platform.String(),
		Contact:  "https://github.com/mmcloughlin/pearl",
	}

	l, err := logger(logfile)
	if err != nil {
		return err
	}

	d := relayData.Data()
	config.Keys, err = d.Keys()
	if err != nil {
		return err
	}

	scope, closer := metrics(l)
	defer check.Close(l, closer)

	r, err := pearl.NewRouter(config, scope, l)
	if err != nil {
		return err
	}

	// Start telemetry server.
	go telemetry.Serve(telemetryAddr, l)

	// Report runtime metrics
	go telemetry.ReportRuntime(scope, 10*time.Second)

	// Start serving
	go func() {
		if err := r.Serve(); err != nil {
			log.Err(l, err, "router error")
		}
	}()

	// Publish to directory authorities
	desc, err := r.Descriptor()
	if err != nil {
		return err
	}
	for _, addr := range authorities.Addresses() {
		err = desc.PublishToAuthority(addr)
		lg := l.With("authority", addr)
		if err != nil {
			log.Err(lg, err, "failed to publish descriptor")
		} else {
			lg.Info("published descriptor")
		}
	}

	select {}
}
