package pearl

import "github.com/pkg/errors"

// Common error types.
var (
	ErrUnexpectedCommand = errors.New("unexpected command")
	ErrShortCellPayload  = errors.New("cell payload too short")
)
