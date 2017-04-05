package log

func ForComponent(logger Logger, name string) Logger {
	return logger.With("component", name)
}
