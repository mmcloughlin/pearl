package pearl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSenderManagerMSB(t *testing.T) {
	managers := []*SenderManager{
		NewSenderManager(false),
		NewSenderManager(true),
	}
	for trial := 0; trial < 10; trial++ {
		for i, m := range managers {
			id, err := m.Add(nil)
			require.NoError(t, err)
			require.Equal(t, i, int(id>>31))
		}
	}
}

func TestSenderManagerAdd(t *testing.T) {
	m := NewSenderManager(true)
	for n := 1; n <= 10000; n++ {
		id, err := m.Add(nil)
		require.NoError(t, err)
		require.NotEqual(t, CircID(0), id)
		require.Len(t, m.senders, n)
	}
}

func TestSenderManagerAddWithID(t *testing.T) {
	m := NewSenderManager(false)
	err := m.AddWithID(7, nil)
	require.NoError(t, err)
	err = m.AddWithID(7, nil)
	assert.EqualError(t, err, "cannot override existing sender id")
}

func TestSenderManagerRemove(t *testing.T) {
	m := NewSenderManager(false)

	err := m.AddWithID(17, nil)
	require.NoError(t, err)

	_, ok := m.Sender(17)
	require.True(t, ok)

	err = m.Remove(217)
	require.EqualError(t, err, "unknown circuit")

	err = m.Remove(17)
	require.NoError(t, err)

	_, ok = m.Sender(17)
	require.False(t, ok)
}

func TestSenderManagerEmpty(t *testing.T) {
	m := NewSenderManager(false)
	for n := 0; n < 4; n++ {
		_, err := m.Add(nil)
		require.NoError(t, err)
	}
	senders := m.Empty()
	assert.Len(t, senders, 4)
}

func TestSenderManagerAddAfterEmpty(t *testing.T) {
	m := NewSenderManager(false)
	m.Empty()
	_, err := m.Add(nil)
	assert.EqualError(t, err, "sender manager closed")
}
