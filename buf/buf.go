// Package buf contains helpers for manipulating byte buffers.
package buf

// Consume n bytes of b and return the rest.
func Consume(b []byte, n int) ([]byte, []byte) {
	return b[:n], b[n:]
}
