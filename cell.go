package pearl

import (
	"encoding/binary"
	"io"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// MaxPayloadLength is the longest allowable cell payload.
//
// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L65
//
//	   PAYLOAD_LEN -- The longest allowable cell payload, in bytes. (509)
//
const MaxPayloadLength = 509

// ErrUnknownCommand is returned when a cell is seen with an unknown command.
var ErrUnknownCommand = errors.New("unknown command")

// CircID is a circuit ID.
type CircID uint32

// IsCommandVariableLength determines whether a cell for the given command
// code is variable length.
func (c Command) IsVariableLength() bool {
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L433-L436
	//
	//	   On a version 2 connection, variable-length cells are indicated by a
	//	   command byte equal to 7 ("VERSIONS").  On a version 3 or
	//	   higher connection, variable-length cells are indicated by a command
	//	   byte equal to 7 ("VERSIONS"), or greater than or equal to 128.
	//
	return (c == CommandVersions) || (byte(c) >= 128)
}

// PayloadOffset computes the payload offset from the start of cell data for the
// given command.
func (c Command) PayloadOffset() int {
	if c.IsVariableLength() {
		return 7
	}
	return 5
}

type Payloaded interface {
	Payload() []byte
}

// Cell represents a cell.
type Cell interface {
	CircID() CircID
	Command() Command
	Payloaded
	Bytes() []byte
}

// CellBuilder can build a cell.
// REVIEW(mbm): CellMarshaler?
type CellBuilder interface {
	Cell() (Cell, error)
}

type CellUnmarshaler interface {
	UnmarshalCell(Cell) error
}

// cell is an implemenation of Cell backed by a byte array.
type cell []byte

// NewCellFromBuffer builds a Cell from the given bytes.
func NewCellFromBuffer(x []byte) Cell {
	return cell(x)
}

// NewCellEmptyPayload builds a variable-length Cell with an empty payload of
// size n bytes.
func NewCellEmptyPayload(circID CircID, cmd Command, n uint16) Cell {
	if !cmd.IsVariableLength() {
		panic("cannot build fixed length cell")
	}

	// BUG(mmcloughlin): NewCellEmptyPayload should use sync.Pool to allocate
	// cell buffers.
	data := make([]byte, 7+int(n))

	binary.BigEndian.PutUint32(data, uint32(circID))
	data[4] = byte(cmd)
	binary.BigEndian.PutUint16(data[5:], n)

	return NewCellFromBuffer(data)
}

// NewFixedCell builds a fixed-size cell.
func NewFixedCell(circID CircID, cmd Command) Cell {
	if cmd.IsVariableLength() {
		panic("command is requires variable length cell")
	}

	// BUG(mmcloughlin): NewFixedCell should use sync.Pool to allocate
	// cell buffers.
	data := make([]byte, 5+MaxPayloadLength)

	binary.BigEndian.PutUint32(data, uint32(circID))
	data[4] = byte(cmd)

	return NewCellFromBuffer(data)
}

// CircID returns the circuit ID from the cell.
func (c cell) CircID() CircID {
	return CircID(binary.BigEndian.Uint32(c))
}

// Command returns the cell command.
func (c cell) Command() Command {
	return Command(c[4])
}

// Payload returns the cell payload.
func (c cell) Payload() []byte {
	return c[c.Command().PayloadOffset():]
}

// Bytes returns the whole cell in bytes.
func (c cell) Bytes() []byte {
	return c
}

type legacyCell struct {
	Cell
}

func NewLegacyCell(c Cell) Cell {
	return legacyCell{
		Cell: c,
	}
}

func (l legacyCell) Bytes() []byte {
	b := l.Cell.Bytes()
	return b[2:]
}

// cellReader reads cells from an io.Reader.
type cellReader struct {
	rd     io.Reader
	logger log.Logger
}

// NewCellReader builds a CellReceiver reading from r.
func NewCellReader(r io.Reader, logger log.Logger) LegacyCellReceiver {
	return cellReader{
		rd:     r,
		logger: log.ForComponent(logger, "cellreader"),
	}
}

// ReceiveCell reads a cell from the underlying io.Reader.
func (r cellReader) ReceiveCell() (Cell, error) {
	return r.receiveCell(4)
}

func (r cellReader) ReceiveLegacyCell() (Cell, error) {
	return r.receiveCell(2)
}

func (r cellReader) receiveCell(circIDLen int) (Cell, error) {
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L391-L404
	//
	//	   On a version 1 connection, each cell contains the following
	//	   fields:
	//
	//	        CircID                                [CIRCID_LEN bytes]
	//	        Command                               [1 byte]
	//	        Payload (padded with 0 bytes)         [PAYLOAD_LEN bytes]
	//
	//	   On a version 2 or higher connection, all cells are as in version 1
	//	   connections, except for variable-length cells, whose format is:
	//
	//	        CircID                                [CIRCID_LEN octets]
	//	        Command                               [1 octet]
	//	        Length                                [2 octets; big-endian integer]
	//	        Payload                               [Length bytes]
	//

	offset := 4 - circIDLen

	// Read cell header
	var hdr [7]byte
	_, err := io.ReadFull(r.rd, hdr[offset:])
	if err != nil {
		return nil, errors.Wrap(err, "could not read cell header")
	}
	r.logger.With("hdr", hdr).Trace("peek cell header")

	// command byte
	cmdByte := hdr[4]
	if !IsCommand(cmdByte) {
		return nil, ErrUnknownCommand
	}
	cmd := Command(cmdByte)
	r.logger.With("command", cmd.String()).Trace("extracted command")

	// fixed vs. variable cell
	payloadLen := uint16(MaxPayloadLength)
	if cmd.IsVariableLength() {
		payloadLen = binary.BigEndian.Uint16(hdr[5:])
	}
	payloadOffset := cmd.PayloadOffset()

	// actually read the cell
	cellLength := payloadOffset + int(payloadLen)
	r.logger.With("len", cellLength).Trace("reading cell")

	// BUG(mmcloughlin) cellReader.ReceiveCell allocates new buffer every time
	// (should use sync.Pool)
	cellBuf := make([]byte, cellLength)
	copy(cellBuf, hdr[:])
	_, err = io.ReadFull(r.rd, cellBuf[7:])
	if err != nil {
		return nil, errors.Wrap(err, "could not read full cell")
	}

	return NewCellFromBuffer(cellBuf), nil
}

// cellWriter writes Cells to an io.Writer.
type cellWriter struct {
	wr     io.Writer
	logger log.Logger
}

func NewCellWriter(w io.Writer, l log.Logger) CellSender {
	return cellWriter{
		wr:     w,
		logger: l,
	}
}

func (w cellWriter) SendCell(cell Cell) error {
	CellLogger(w.logger, cell).Trace("sending cell")
	_, err := w.wr.Write(cell.Bytes())
	return err
}

func BuildAndSend(s CellSender, b CellBuilder) error {
	cell, err := b.Cell()
	if err != nil {
		return errors.Wrap(err, "error building cell")
	}

	err = s.SendCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not send cell")
	}

	return nil

}
