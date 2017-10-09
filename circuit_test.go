package pearl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCircID2(t *testing.T) {
	f := CircID2Format{}
	assert.Equal(t, CircID(0), GenerateCircID(f, 0)>>15)
	assert.Equal(t, CircID(1), GenerateCircID(f, 1)>>15)
}

func TestGenerateCircID4(t *testing.T) {
	f := CircID4Format{}
	assert.Equal(t, CircID(0), GenerateCircID(f, 0)>>31)
	assert.Equal(t, CircID(1), GenerateCircID(f, 1)>>31)
}

func TestGenerateCircID4Rand(t *testing.T) {
	f := CircID4Format{}
	assert.NotEqual(t, GenerateCircID(f, 0), GenerateCircID(f, 0))
}
