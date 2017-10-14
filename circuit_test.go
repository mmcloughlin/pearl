package pearl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCircID4(t *testing.T) {
	assert.Equal(t, CircID(0), GenerateCircID(0)>>31)
	assert.Equal(t, CircID(1), GenerateCircID(1)>>31)
}

func TestGenerateCircID4Rand(t *testing.T) {
	assert.NotEqual(t, GenerateCircID(0), GenerateCircID(0))
}
