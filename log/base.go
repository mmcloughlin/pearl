// Package log defines standard logging for pearl.
package log

import "github.com/inconshreveable/log15"

// Level is a logging level.
type Level int

// Defined logging levels.
const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelNotice
	LevelWarn
	LevelError
)

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

// Log logs msg at level with the given Logger.
func Log(l Logger, lvl Level, msg string) {
	switch lvl {
	case LevelTrace:
		l.Trace(msg)
	case LevelDebug:
		l.Debug(msg)
	case LevelInfo:
		l.Info(msg)
	case LevelNotice:
		l.Notice(msg)
	case LevelWarn:
		l.Warn(msg)
	case LevelError:
		l.Error(msg)
	default:
		panic("unknown level")
	}
}

type log15Adaptor struct {
	base log15.Logger
	ctx  log15.Ctx
}

func (l log15Adaptor) With(k string, v interface{}) Logger {
	newCtx := log15.Ctx{}
	for key, val := range l.ctx {
		newCtx[key] = val
	}
	newCtx[k] = v
	return log15Adaptor{
		base: l.base,
		ctx:  newCtx,
	}
}

func (l log15Adaptor) logger() log15.Logger {
	return l.base.New(l.ctx)
}

func (l log15Adaptor) Trace(msg string)  { l.Debug(msg) }
func (l log15Adaptor) Debug(msg string)  { l.logger().Debug(msg) }
func (l log15Adaptor) Info(msg string)   { l.logger().Info(msg) }
func (l log15Adaptor) Notice(msg string) { l.Info(msg) }
func (l log15Adaptor) Warn(msg string)   { l.logger().Warn(msg) }
func (l log15Adaptor) Error(msg string)  { l.logger().Error(msg) }

// NewDebug builds a logger intended for debugging purposes.
func NewDebug() Logger {
	return log15Adaptor{
		base: log15.New(),
	}
}
