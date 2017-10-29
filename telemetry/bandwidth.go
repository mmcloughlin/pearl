package telemetry

import (
	"io"

	"github.com/uber-go/tally"
)

type Bandwidth struct {
	tally.Counter
}

func NewBandwidth(c tally.Counter) *Bandwidth {
	return &Bandwidth{
		Counter: c,
	}
}

func (b *Bandwidth) Write(d []byte) (int, error) {
	n := len(d)
	b.Inc(int64(n))
	return n, nil
}

func (b *Bandwidth) WrapReader(r io.Reader) io.Reader {
	return io.TeeReader(r, b)
}

func (b *Bandwidth) WrapWriter(w io.Writer) io.Writer {
	return io.MultiWriter(w, b)
}
