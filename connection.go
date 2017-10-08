package pearl

import (
	"encoding/hex"
	"net"

	"github.com/mmcloughlin/pearl/tls"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// Connection encapsulates a router connection.
type Connection struct {
	router     *Router
	tlsCtx     *TLSContext
	tlsConn    *tls.Conn
	cellReader CellReader

	proto    LinkProtocolVersion
	circuits *CircuitManager

	logger log.Logger
}

// NewServer constructs a server connection.
func NewServer(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ServerConn(conn)
	return newConnection(r, tlsCtx, tlsConn, logger.With("role", "server")), nil
}

// NewClient constructs a client-side connection.
func NewClient(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ClientConn(conn)
	return newConnection(r, tlsCtx, tlsConn, logger.With("role", "client")), nil
}

func newConnection(r *Router, tlsCtx *TLSContext, tlsConn *tls.Conn, logger log.Logger) *Connection {
	return &Connection{
		router:     r,
		tlsCtx:     tlsCtx,
		tlsConn:    tlsConn,
		cellReader: NewCellReader(tlsConn, logger),

		proto:    LinkProtocolNone,
		circuits: NewCircuitManager(),

		logger: logger.With("raddr", tlsConn.RemoteAddr()),
	}
}

// Handle handles the full lifecycle of the connection.
func (c *Connection) Handle() {
	c.logger.Info("handle")

	err := c.serverHandshake()
	if err != nil {
		log.Err(c.logger, err, "error handling connection")
	}
}

func (c *Connection) serverHandshake() error {
	// Establish link protocol version
	clientVersions, err := c.receiveVersions()
	if err != nil {
		return errors.Wrap(err, "failed to determine client versions")
	}

	err = c.sendVersions(SupportedLinkProtocolVersions)
	if err != nil {
		return errors.Wrap(err, "failed to send supported versions")
	}

	c.establishVersion(clientVersions, SupportedLinkProtocolVersions)

	f := c.proto.CellFormat()

	// Send certs cell
	//
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L567-L569
	//
	//	   To authenticate the responder, the initiator MUST check the following:
	//	     * The CERTS cell contains exactly one CertType 1 "Link" certificate.
	//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	//
	certsCell := &CertsCell{}
	certsCell.AddCert(LinkCert, c.tlsCtx.LinkCert)
	certsCell.AddCert(IdentityCert, c.tlsCtx.IDCert)

	cell, err := certsCell.Cell(f)
	if err != nil {
		return errors.Wrap(err, "error building certs cell")
	}

	_, err = c.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send certs cell")
	}

	c.logger.Debug("sent certs cell")

	// Send auth challenge cell
	authChallengeCell, err := NewAuthChallengeCellStandard()
	if err != nil {
		return errors.Wrap(err, "error initializing auth challenge cell")
	}

	cell, err = authChallengeCell.Cell(f)
	if err != nil {
		return errors.Wrap(err, "error building auth challenge cell")
	}

	_, err = c.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send auth challenge cell")
	}

	c.logger.Debug("sent auth challenge cell")

	// Send NETINFO cell
	netInfoCell, err := NewNetInfoCellFromConn(c.tlsConn)
	if err != nil {
		return errors.Wrap(err, "error initializing net info cell")
	}

	cell, err = netInfoCell.Cell(f)
	if err != nil {
		return errors.Wrap(err, "error building net info cell")
	}

	_, err = c.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send net info cell")
	}

	c.logger.Debug("sent net info cell")

	// Process handshake cells
	err = c.execute(HandshakeHandler)
	if err != nil {
		return err
	}

	// Enter main loop
	err = c.execute(RunLoopHandler)
	if err != nil {
		return err
	}

	return nil
}

func (c *Connection) clientHandshake() error {
	// Establish link protocol version
	err := c.sendVersions(SupportedLinkProtocolVersions)
	if err != nil {
		return errors.Wrap(err, "failed to send supported versions")
	}

	serverVersions, err := c.receiveVersions()
	if err != nil {
		return errors.Wrap(err, "failed to determine server versions")
	}

	c.establishVersion(serverVersions, SupportedLinkProtocolVersions)

	//f := c.proto.CellFormat()

	/*
		// Send certs cell
		//
		// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L567-L569
		//
		//	   To authenticate the responder, the initiator MUST check the following:
		//	     * The CERTS cell contains exactly one CertType 1 "Link" certificate.
		//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
		//
		certsCell := &CertsCell{}
		certsCell.AddCert(LinkCert, c.tlsCtx.LinkCert)
		certsCell.AddCert(IdentityCert, c.tlsCtx.IDCert)

		cell, err = certsCell.Cell(f)
		if err != nil {
			return errors.Wrap(err, "error building certs cell")
		}

		_, err = c.tlsConn.Write(cell.Bytes())
		if err != nil {
			return errors.Wrap(err, "could not send certs cell")
		}

		c.logger.Debug("sent certs cell")

		// Send auth challenge cell
		authChallengeCell, err := NewAuthChallengeCellStandard()
		if err != nil {
			return errors.Wrap(err, "error initializing auth challenge cell")
		}

		cell, err = authChallengeCell.Cell(f)
		if err != nil {
			return errors.Wrap(err, "error building auth challenge cell")
		}

		_, err = c.tlsConn.Write(cell.Bytes())
		if err != nil {
			return errors.Wrap(err, "could not send auth challenge cell")
		}

		c.logger.Debug("sent auth challenge cell")

		// Send NETINFO cell
		netInfoCell, err := NewNetInfoCellFromConn(c.tlsConn)
		if err != nil {
			return errors.Wrap(err, "error initializing net info cell")
		}

		cell, err = netInfoCell.Cell(f)
		if err != nil {
			return errors.Wrap(err, "error building net info cell")
		}

		_, err = c.tlsConn.Write(cell.Bytes())
		if err != nil {
			return errors.Wrap(err, "could not send net info cell")
		}

		c.logger.Debug("sent net info cell")

		// Process handshake cells
		err = c.execute(HandshakeHandler)
		if err != nil {
			return err
		}

		// Enter main loop
		err = c.execute(RunLoopHandler)
		if err != nil {
			return err
		}

	*/

	return nil
}

// receiveVersions expects a VERSIONS cell and returns the contained
// LinkProtocolVersions.
func (c *Connection) receiveVersions() ([]LinkProtocolVersion, error) {
	// Expect a versions cell. Note this has circID length 2 regardless of link
	// protocol version.
	//
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L411-L413
	//
	//	   CIRCID_LEN is 2 for link protocol versions 1, 2, and 3.  CIRCID_LEN
	//	   is 4 for link protocol version 4 or higher.  The VERSIONS cell itself
	//	   always has CIRCID_LEN == 2 for backward compatibility.
	//
	cell, err := c.cellReader.ReadCell(VersionsCellFormat)
	if err != nil {
		return nil, errors.Wrap(err, "could not read cell")
	}

	versionsCell, err := ParseVersionsCell(cell)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse versions cell")
	}

	c.logger.With("supported_versions", versionsCell.SupportedVersions).Debug("received versions cell")

	return versionsCell.SupportedVersions, nil
}

// sendVersions sends a VERSIONS cell with the given list of protocol versions.
func (c *Connection) sendVersions(v []LinkProtocolVersion) error {
	ourVersionsCell := VersionsCell{
		SupportedVersions: v,
	}
	cell, err := ourVersionsCell.Cell(VersionsCellFormat)
	if err != nil {
		return errors.Wrap(err, "error building versions cell")
	}

	_, err = c.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send versions cell")
	}

	c.logger.With("supported_versions", v).Debug("sent versions cell")

	return nil
}

// establishVersion reconciles two supported versions list and sets the proto
// field.
func (c *Connection) establishVersion(a, b []LinkProtocolVersion) error {
	proto, err := ResolveVersion(a, b)
	if err != nil {
		return errors.Wrap(err, "could not agree on link protocol version")
	}

	c.logger.With("version", proto).Info("determined link protocol version")
	c.proto = proto

	return nil
}

func (c *Connection) execute(h Handler) error {
	var err error
	var cell Cell
	for {
		cell, err = c.cellReader.ReadCell(c.proto.CellFormat())
		if err != nil {
			return errors.Wrap(err, "could not read cell")
		}

		c.logger.
			With("cmd", cell.Command()).
			With("circid", cell.CircID()).
			With("payload", hex.EncodeToString(cell.Payload())).
			With("bytes", hex.EncodeToString(cell.Bytes())).
			Trace("received cell")

		err = h.HandleCell(c, cell)
		if err == EOH {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// HandshakeHandler handles cells during server side handshake.
var HandshakeHandler = NewDirector(map[Command]Handler{
	Padding:      IgnoreHandler,
	Certs:        NotImplementedHandler,
	Authenticate: NotImplementedHandler,
	Netinfo:      HandlerFunc(func(_ *Connection, _ Cell) error { return EOH }),
})

// HandshakeHandler handles cells during handshake.
var RunLoopHandler = NewDirector(map[Command]Handler{
	Padding:    IgnoreHandler,
	Create2:    HandlerFunc(Create2Handler),
	Create:     NotImplementedHandler,
	Destroy:    NotImplementedHandler,
	RelayEarly: HandlerFunc(RelayHandler),
})

// EOH is a special error type used to indicate that cell handling should stop.
var EOH = errors.New("end of handlers")

// Handler is something that can handle a cell.
type Handler interface {
	HandleCell(*Connection, Cell) error
}

// HandlerFunc allows implementation of Handler interface with a plain function.
type HandlerFunc func(*Connection, Cell) error

// HandleCell calls f.
func (f HandlerFunc) HandleCell(conn *Connection, c Cell) error {
	return f(conn, c)
}

// LoggingHander builds a Handler that logs a Cell and does nothing else.
func LoggingHander(lvl log.Level, msg string) Handler {
	return HandlerFunc(func(conn *Connection, c Cell) error {
		log.Log(conn.logger.With("cmd", c.Command()), lvl, msg)
		return nil
	})
}

// Convenience logging handlers.
var (
	IgnoreHandler         = LoggingHander(log.LevelDebug, "ignoring cell")
	NotImplementedHandler = LoggingHander(log.LevelError, "cell handler not implemented")
)

// Director is a Handler that routes Cells to sub-handlers based on command type.
type Director struct {
	handlers map[Command]Handler
}

// NewDirector builds a Director with the given handlers.
func NewDirector(handlers map[Command]Handler) *Director {
	return &Director{
		handlers: handlers,
	}
}

// NewDirectorEmpty builds a Director with no handlers.
func NewDirectorEmpty() *Director {
	return NewDirector(make(map[Command]Handler))
}

// AddHandler adds a handler for the given command type.
func (d *Director) AddHandler(cmd Command, h Handler) {
	d.handlers[cmd] = h
}

// HandleCell handles c.
func (d *Director) HandleCell(conn *Connection, c Cell) error {
	h, found := d.handlers[c.Command()]
	if !found {
		return ErrUnexpectedCommand
	}
	return h.HandleCell(conn, c)
}
