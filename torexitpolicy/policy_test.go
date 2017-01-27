package torexitpolicy

import (
	"io"
	"math/rand"
	"net"
	"testing"

	"github.com/mmcloughlin/pearl/torexitpolicy/mocks"
	"github.com/stretchr/testify/assert"
)

var rnd = rand.New(rand.NewSource(1))

func RandIP() net.IP {
	b := make([]byte, 16)
	_, err := io.ReadFull(rnd, b)
	if err != nil {
		panic(err)
	}
	return net.IP(b)
}

func RandIPPort() (net.IP, uint16) {
	return RandIP(), uint16(rnd.Uint32())
}

func TestActionDescribe(t *testing.T) {
	assert.Equal(t, "accept", Accept.Describe())
	assert.Equal(t, "reject", Reject.Describe())
}

func TestAllPatternMatches(t *testing.T) {
	for i := 0; i < 100; i++ {
		assert.True(t, AllPattern.Matches(RandIPPort()))
	}
}

func TestAllPatternDescribe(t *testing.T) {
	assert.Equal(t, "*:*", AllPattern.Describe())
}

func TestRejectAllPolicy(t *testing.T) {
	for i := 0; i < 100; i++ {
		assert.False(t, RejectAllPolicy.Allow(RandIPPort()))
	}
}

func TestAcceptAllPolicy(t *testing.T) {
	for i := 0; i < 100; i++ {
		assert.True(t, AcceptAllPolicy.Allow(RandIPPort()))
	}
}

func TestPolicyAllow(t *testing.T) {
	ip, port := RandIPPort()

	p := NewPolicy()

	nomatch := &mocks.Pattern{}
	nomatch.On("Matches", ip, port).Return(false).Twice()
	p.Reject(nomatch)
	p.Accept(nomatch)

	match := &mocks.Pattern{}
	match.On("Matches", ip, port).Return(true).Once()
	p.Accept(match)

	assert.True(t, p.Allow(ip, port))
	nomatch.AssertExpectations(t)
	match.AssertExpectations(t)
}

func TestPolicyAllowDefault(t *testing.T) {
	ip, port := RandIPPort()

	p := NewPolicy()

	nomatch := &mocks.Pattern{}
	nomatch.On("Matches", ip, port).Return(false).Times(4)
	p.Reject(nomatch)
	p.Accept(nomatch)
	p.Reject(nomatch)
	p.Accept(nomatch)

	assert.False(t, p.Allow(ip, port))
	nomatch.AssertExpectations(t)
}

func TestPolicyAllowRules(t *testing.T) {
	p := NewPolicy()

	m := &mocks.Pattern{}
	m.On("Describe").Return("127.0.0.1:9000").Twice()
	p.Reject(m)
	p.Accept(m)

	expect := []string{
		"reject 127.0.0.1:9000",
		"accept 127.0.0.1:9000",
		"reject *:*",
	}

	lines := []string{}
	for _, r := range p.Rules() {
		line := r.Action.Describe() + " " + r.Pattern.Describe()
		lines = append(lines, line)
	}

	assert.Equal(t, expect, lines)
	m.AssertExpectations(t)
}
