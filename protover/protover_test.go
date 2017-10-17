package protover

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSupportedProtocols(t *testing.T) {
	s := New()
	s.Supports(Relay, SingleVersion(2))
	s.Supports(Relay, NewVersionRange(4, 7))
	s.Supports(Desc, NewVersionRange(4, 5))
	s.Supports(HSRend, SingleVersion(42))
	assert.Equal(t, "Desc=4-5 HSRend=42 Relay=2,4-7", s.String())
}
