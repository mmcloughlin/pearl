package pearl

import "hash"

// HashedCellReader maintains a running digest of all cells it receives.
type HashedCellReader struct {
	r CellReader
	h hash.Hash
}

var _ CellReader = new(HashedCellReader)

// NewHashedCellReader reads cells from c and hashes them with h.
func NewHashedCellReader(r CellReader, h hash.Hash) *HashedCellReader {
	return &HashedCellReader{
		r: r,
		h: h,
	}
}

// ReadCell reads a cell and hashes it.
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
