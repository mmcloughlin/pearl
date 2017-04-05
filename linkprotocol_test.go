package pearl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveVersion(t *testing.T) {
	a := []LinkProtocolVersion{1, 2, 3, 4, 5}
	b := []LinkProtocolVersion{4, 6, 7, 8, 9}
	v, err := ResolveVersion(a, b)
	assert.Equal(t, v, LinkProtocolVersion(4))
	assert.NoError(t, err)
}

func TestResolveVersionNoCommonVersion(t *testing.T) {
	a := []LinkProtocolVersion{1, 2, 3}
	b := []LinkProtocolVersion{4, 5, 6}
	v, err := ResolveVersion(a, b)
	assert.Equal(t, v, LinkProtocolNone)
	assert.Equal(t, err, ErrNoCommonVersion)
}
