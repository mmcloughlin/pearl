package log

// ForComponent adds a tag to the logger labelling the component the logger is
// for.
func ForComponent(logger Logger, name string) Logger {
	return logger.With("component", name)
}
