package pearl

import "errors"

// ErrUnexpectedCommand occurs when a command was not expected.
var ErrUnexpectedCommand = errors.New("unexpected command")
