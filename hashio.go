package pearl

import "hash"

type HashedCellReader struct {
	r CellReader
	h hash.Hash
}

var _ CellReader = new(HashedCellReader)

func NewHashedCellReader(r CellReader, h hash.Hash) *HashedCellReader {
	return &HashedCellReader{
		r: r,
		h: h,
	}
}

func (h *HashedCellReader) ReadCell(f CellFormat) (Cell, error) {
	c, err := h.r.ReadCell(f)
	if err != nil {
		return nil, err
	}

	_, err = h.h.Write(c.Bytes())
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (h *HashedCellReader) Sum(b []byte) []byte {
	return h.h.Sum(b)
}
