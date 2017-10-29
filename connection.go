package pearl

import (
	"bufio"
	"io"
	"net"

	"go.uber.org/multierr"

	"github.com/mmcloughlin/pearl/check"
	"github.com/mmcloughlin/pearl/fork/tls"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

const (
	maxTLSRecordSize      = 16384 // 16 KiB
	defaultReadBufferSize = 2 * maxTLSRecordSize
)

// Connection encapsulates a router connection.
type Connection struct {
	router      *Router
	tlsCtx      *TLSContext
	tlsConn     *tls.Conn
	connID      ConnID
	fingerprint []byte

	circuits *SenderManager

	r io.Reader
	w io.Writer
	CellReceiver
	CellSender

	logger log.Logger
}

// NewServer constructs a server connection.
func NewServer(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ServerConn(conn)
	c := newConnection(r, tlsCtx, tlsConn, false, logger.With("role", "server"))
	return c, nil
}

// NewClient constructs a client-side connection.
func NewClient(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ClientConn(conn)
	c := newConnection(r, tlsCtx, tlsConn, true, logger.With("role", "client"))
	return c, nil
}

func newConnection(r *Router, tlsCtx *TLSContext, tlsConn *tls.Conn, outbound bool, logger log.Logger) *Connection {
	connID := NewConnID()
	rd := bufio.NewReaderSize(r.metrics.Inbound.WrapReader(tlsConn), defaultReadBufferSize)
	wr := r.metrics.Outbound.WrapWriter(tlsConn) // TODO(mbm): use bufio
	r.metrics.Connections.Alloc()
	return &Connection{
		router:      r,
		tlsCtx:      tlsCtx,
		tlsConn:     tlsConn,
		connID:      connID,
		fingerprint: nil,

		circuits: NewSenderManager(outbound),

		r:            rd,
		w:            wr,
		CellReceiver: NewCellReader(rd, logger),
		CellSender:   NewCellWriter(wr, logger),

		logger: log.ForConn(logger, tlsConn).With("conn_id", connID),
	}
}

func (c *Connection) newHandshake() *Handshake {
	return &Handshake{
		Conn:        c.tlsConn,
		Link:        NewHandshakeLink(c.r, c.w, c.logger),
		TLSContext:  c.tlsCtx,
		IdentityKey: &c.router.IdentityKey().PublicKey,
		logger:      c.logger,
	}
}

func (c *Connection) ConnID() ConnID {
	return c.connID
}

// Fingerprint returns the fingerprint of the connected peer.
func (c *Connection) Fingerprint() (Fingerprint, error) {
	if c.fingerprint == nil {
		return Fingerprint{}, errors.New("peer fingerprint not established")
	}
	return NewFingerprintFromBytes(c.fingerprint)
}

func (c *Connection) Serve() error {
	c.logger.Info("serving new connection")

	h := c.newHandshake()
	err := h.Server()
	if err != nil {
		log.Err(c.logger, err, "server handshake failed")
		return nil
	}
	c.fingerprint = h.PeerFingerprint
	c.logger.Info("handshake complete")

	if err := c.router.connections.AddConnection(c); err != nil {
		return err
	}

	c.loop()
	return nil
}

func (c *Connection) StartClient() error {
	h := c.newHandshake()
	err := h.Client()
	if err != nil {
		return errors.Wrap(err, "client handshake failed")
	}
	c.fingerprint = h.PeerFingerprint
	c.logger.Info("handshake complete")

	if err := c.router.connections.AddConnection(c); err != nil {
		return err
	}

	// TODO(mbm): goroutine management
	go c.loop()

	return nil
}

func (c *Connection) loop() {
	var err error
	for err == nil {
		err = c.oneCell()
	}

	c.logger.Debug("exit read loop")
	if !check.EOF(err) {
		log.Err(c.logger, err, "cell handling error")
	}

	if err := c.cleanup(); err != nil {
		log.WithErr(c.logger, err).Debug("connection cleanup error")
	}
}

func (c *Connection) oneCell() error {
	cell, err := c.ReceiveCell()
	if err != nil {
		return err
	}

	logger := CellLogger(c.logger, cell)
	logger.Trace("received cell")

	switch cell.Command() {
	// Cells to be handled by this Connection
	case CommandCreate:
		err = CreateHandler(c, cell) // XXX error return
		if err != nil {
			log.Err(logger, err, "failed to handle create")
		}
	case CommandCreate2:
		err = Create2Handler(c, cell) // XXX error return
		if err != nil {
			log.Err(logger, err, "failed to handle create2")
		}
		// Cells related to a circuit
	case CommandCreated, CommandCreated2, CommandRelay, CommandRelayEarly, CommandDestroy:
		logger.Trace("directing cell to circuit channel")
		s, ok := c.circuits.Sender(cell.CircID())
		if !ok {
			// BUG(mbm): is logging the correct behavior
			logger.Error("unrecognized circ id")
			return nil
		}
		err = s.SendCell(cell)
		if err != nil {
			logger.Error("failed to send cell to circuit")
		}
	// Cells to be ignored
	case CommandPadding, CommandVpadding:
		logger.Debug("skipping padding cell")
	// Something which shouldn't happen
	default:
		logger.Error("no handler registered")
	}
	return nil
}

// cleanup cleans up resources related to the connection.
func (c *Connection) cleanup() error {
	c.logger.Info("cleanup connection")
	c.router.metrics.Connections.Free()

	var result error
	for _, circ := range c.circuits.Empty() {
		if err := circ.Close(); err != nil {
			result = multierr.Append(result, err)
		}
	}

	return multierr.Combine(
		result,
		c.router.connections.RemoveConnection(c),
		c.tlsConn.Close(), // BUG(mbm): potential double close?
	)
}

func CellLogger(l log.Logger, cell Cell) log.Logger {
	return l.With("cmd", cell.Command()).With("circid", cell.CircID())
}
