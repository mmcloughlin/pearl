package pearl

type DestroyCell struct {
	CircID CircID
	Reason CircuitErrorCode
}

func NewDestroyCell(id CircID, reason CircuitErrorCode) *DestroyCell {
	return &DestroyCell{
		CircID: id,
		Reason: reason,
	}
}

func ParseDestroyCell(c Cell) (*DestroyCell, error) {
	// Insert: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L1331-L1335
	p := c.Payload()
	if len(p) < 1 {
		return nil, ErrShortCellPayload
	}
	reason := CircuitErrorCode(p[0])

	return &DestroyCell{
		CircID: c.CircID(),
		Reason: reason,
	}, nil
}

func (d DestroyCell) Cell() Cell {
	c := NewFixedCell(d.CircID, Destroy)
	p := c.Payload()
	p[0] = byte(d.Reason)
	return c
}
