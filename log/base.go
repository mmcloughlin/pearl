// Package log defines standard logging for pearl.
package log

import "github.com/inconshreveable/log15"

// Logger is the base interface for logging in the pearl packages.
type Logger interface {
	// With adds key value pair(s) to the logging context.
	With(ctx ...interface{}) Logger

	// Logging at levels used in the official Tor client.
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Notice(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
}

type log15Adaptor struct {
	log15.Logger
}

func (l log15Adaptor) With(ctx ...interface{}) Logger {
	return log15Adaptor{
		Logger: l.New(ctx...),
	}
}

func (l log15Adaptor) Notice(msg string, ctx ...interface{}) {
	l.Info(msg, ctx...)
}

// NewDebug builds a logger intended for debugging purposes.
func NewDebug() Logger {
	return log15Adaptor{
		Logger: log15.New(),
	}
}
