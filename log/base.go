// Package log defines standard logging for pearl.
package log

import "github.com/inconshreveable/log15"

// Logger is the base interface for logging in the pearl packages.
type Logger interface {
	// With adds key value pair(s) to the logging context.
	With(string, interface{}) Logger

	// Logging at levels used in the official Tor client.
	Trace(msg string)
	Debug(msg string)
	Info(msg string)
	Notice(msg string)
	Warn(msg string)
	Error(msg string)
}

type log15Adaptor struct {
	log15.Logger
}

func (l log15Adaptor) With(k string, v interface{}) Logger {
	return log15Adaptor{
		Logger: l.New(k, v),
	}
}

func (l log15Adaptor) Trace(msg string)  { l.Logger.Debug(msg) }
func (l log15Adaptor) Debug(msg string)  { l.Logger.Debug(msg) }
func (l log15Adaptor) Info(msg string)   { l.Logger.Info(msg) }
func (l log15Adaptor) Notice(msg string) { l.Logger.Info(msg) }
func (l log15Adaptor) Warn(msg string)   { l.Logger.Warn(msg) }
func (l log15Adaptor) Error(msg string)  { l.Logger.Error(msg) }

// NewDebug builds a logger intended for debugging purposes.
func NewDebug() Logger {
	return log15Adaptor{
		Logger: log15.New(),
	}
}
