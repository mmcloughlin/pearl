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
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L1331-L1335
	//
	//	   The payload of a RELAY_TRUNCATED or DESTROY cell contains a single octet,
	//	   describing why the circuit is being closed or truncated.  When sending a
	//	   TRUNCATED or DESTROY cell because of another TRUNCATED or DESTROY cell,
	//	   the error code should be propagated.  The origin of a circuit always sets
	//	   this error code to 0, to avoid leaking its version.
	//
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
