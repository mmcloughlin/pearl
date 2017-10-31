// Package telemetry provides monitoring utilities.
package telemetry

import (
	"expvar"
	"net/http"
	"net/http/pprof"

	"github.com/mmcloughlin/pearl/log"
)

// Handler returns a HTTP handler for telemetry endpoints.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/debug/vars", expvar.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// Serve launches a HTTP server for telemetry endpoints.
func Serve(addr string, l log.Logger) {
	if err := http.ListenAndServe(addr, Handler()); err != nil {
		log.Err(l, err, "telemetry server failure")
	}
}
