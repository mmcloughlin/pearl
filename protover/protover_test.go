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

func TestRecommendedRequired(t *testing.T) {
	clientProto := "Cons=1-2 Desc=1-2 DirCache=1 HSDir=2 HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2"
	relayProto := "Cons=1 Desc=1 DirCache=1 HSDir=2 HSIntro=3 HSRend=1 Link=3-4 LinkAuth=1 Microdesc=1 Relay=1-2"
	assert.Equal(t, clientProto, ClientRequired.String())
	assert.Equal(t, clientProto, ClientRecommended.String())
	assert.Equal(t, relayProto, RelayRequired.String())
	assert.Equal(t, clientProto, RelayRecommended.String())
}
