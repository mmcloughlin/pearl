package check

import (
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestEOF(t *testing.T) {
	cases := []struct {
		Err    error
		Result bool
	}{
		{io.EOF, true},
		{errors.Wrap(io.EOF, "end of something"), true},
		{assert.AnError, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.Result, EOF(c.Err))
	}
}
