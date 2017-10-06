package log

import "encoding/hex"

// ForComponent adds a tag to the logger labelling the component the logger is
// for.
func ForComponent(logger Logger, name string) Logger {
	return logger.With("component", name)
}

func WithBytes(logger Logger, key string, data []byte) Logger {
	return logger.With(key, hex.EncodeToString(data))
}

// Err logs an error with an additional message.
func Err(logger Logger, err error, msg string) {
	logger.With("err", err.Error()).Error(msg)
}
