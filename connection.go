package pearl

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net"

	"github.com/mmcloughlin/pearl/tls"
	"github.com/mmcloughlin/pearl/torcrypto"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// Connection encapsulates a router connection.
type Connection struct {
	router  *Router
	tlsCtx  *TLSContext
	tlsConn *tls.Conn

	proto    LinkProtocolVersion
	circuits *CircuitManager

	rd           io.Reader
	wr           io.Writer
	cellReader   CellReader
	inboundHash  hash.Hash
	outboundHash hash.Hash

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
	// BUG(mbm): massively inefficient to always hash io (only required for AUTH_CHALLENGE/AUTHENTICATE)
	inboundHash := sha256.New()
	outboundHash := sha256.New()
	rd := io.TeeReader(tlsConn, inboundHash)
	wr := io.MultiWriter(tlsConn, outboundHash)

	return &Connection{
		router:  r,
		tlsCtx:  tlsCtx,
		tlsConn: tlsConn,

		proto:    LinkProtocolNone,
		circuits: NewCircuitManager(),

		rd:           rd,
		wr:           wr,
		cellReader:   NewCellReader(rd, logger),
		inboundHash:  inboundHash,
		outboundHash: outboundHash,

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

	// Send certs cell
	//
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L567-L569
	//
	//	   To authenticate the responder, the initiator MUST check the following:
	//	     * The CERTS cell contains exactly one CertType 1 "Link" certificate.
	//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	//
	certsCell := &CertsCell{}
	certsCell.AddCert(CertTypeLink, c.tlsCtx.LinkCert)
	certsCell.AddCert(CertTypeIdentity, c.tlsCtx.IDCert)

	err = c.sendCell(certsCell)
	if err != nil {
		return errors.Wrap(err, "could not send certs cell")
	}

	// Send auth challenge cell
	authChallengeCell, err := NewAuthChallengeCellStandard()
	if err != nil {
		return errors.Wrap(err, "error initializing auth challenge cell")
	}

	err = c.sendCell(authChallengeCell)
	if err != nil {
		return errors.Wrap(err, "could not send auth challenge cell")
	}

	// Send NETINFO
	err = c.sendNetInfoCell()
	if err != nil {
		return errors.Wrap(err, "failed to send net info")
	}

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
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L509-L523
	//
	//	   When the in-protocol handshake is used, the initiator sends a
	//	   VERSIONS cell to indicate that it will not be renegotiating.  The
	//	   responder sends a VERSIONS cell, a CERTS cell (4.2 below) to give the
	//	   initiator the certificates it needs to learn the responder's
	//	   identity, an AUTH_CHALLENGE cell (4.3) that the initiator must include
	//	   as part of its answer if it chooses to authenticate, and a NETINFO
	//	   cell (4.5).  As soon as it gets the CERTS cell, the initiator knows
	//	   whether the responder is correctly authenticated.  At this point the
	//	   initiator behaves differently depending on whether it wants to
	//	   authenticate or not. If it does not want to authenticate, it MUST
	//	   send a NETINFO cell.  If it does want to authenticate, it MUST send a
	//	   CERTS cell, an AUTHENTICATE cell (4.4), and a NETINFO.  When this
	//	   handshake is in use, the first cell must be VERSIONS, VPADDING, or
	//	   AUTHORIZE, and no other cell type is allowed to intervene besides
	//	   those specified, except for VPADDING cells.
	//

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

	// Receive CERTS cell
	cell, err := c.cellReader.ReadCell(c.proto.CellFormat())
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	peerCertsCell, err := ParseCertsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse certs cell")
	}

	c.logger.With("numcerts", len(peerCertsCell.Certs)).Debug("received certs cell")
	c.logger.Error("certificate cell verification not implemented")

	// Receive AUTH_CHALLENGE cell
	cell, err = c.cellReader.ReadCell(c.proto.CellFormat())
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	authChallengeCell, err := ParseAuthChallengeCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse auth challenge cell")
	}

	log.WithBytes(c.logger, "challenge", authChallengeCell.Challenge[:]).Debug("received auth challenge cell")
	c.logger.Error("auth challenge reply not implemented")

	// Receive NETINFO cell
	cell, err = c.cellReader.ReadCell(c.proto.CellFormat())
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	netInfoCell, err := ParseNetInfoCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse netinfo cell")
	}

	c.logger.With("receiver_addr", netInfoCell.ReceiverAddress).Debug("received net info cell")
	c.logger.Error("net info processing not implemented")

	// Send CERTS cell:
	//
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L716-L721
	//
	//	   If an initiator wants to authenticate, it responds to the
	//	   AUTH_CHALLENGE cell with a CERTS cell and an AUTHENTICATE cell.
	//	   The CERTS cell is as a server would send, except that instead of
	//	   sending a CertType 1 (and possibly CertType 5) certs for arbitrary link
	//	   certificates, the initiator sends a CertType 3 (and possibly
	//	   CertType 6) cert for an RSA/Ed25519 AUTHENTICATE key.
	//
	// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L678-L681
	//
	//	   To authenticate the initiator as having an RSA identity key only,
	//	   the responder MUST check the following:
	//	     * The CERTS cell contains exactly one CertType 3 "AUTH" certificate.
	//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	//
	certsCell := &CertsCell{}
	certsCell.AddCert(CertTypeIdentity, c.tlsCtx.IDCert)
	certsCell.AddCert(CertTypeAuth, c.tlsCtx.AuthCert)

	err = c.sendCell(certsCell)
	if err != nil {
		return errors.Wrap(err, "could not send certs cell")
	}

	// TODO(mbm): send AUTHENTICATE cell in client handshake
	if !authChallengeCell.SupportsMethod(AuthMethodRSASHA256TLSSecret) {
		return errors.New("server does not support auth method")
	}

	serverLinkCert := peerCertsCell.Lookup(CertTypeLink)
	if serverLinkCert == nil {
		return errors.New("missing server link cert")
	}

	serverIDCertDER := peerCertsCell.Lookup(CertTypeIdentity)
	if serverIDCertDER == nil {
		return errors.New("missing server identity cert")
	}

	serverIDKey, err := torcrypto.ParseRSAPublicKeyFromCertificateDER(serverIDCertDER)
	if err != nil {
		return errors.Wrap(err, "failed to extract server identity key")
	}

	cs := c.tlsConn.ConnectionState()
	a := &AuthRSASHA256TLSSecret{
		AuthKey:           c.tlsCtx.AuthKey,
		ClientIdentityKey: &c.router.idKey.PublicKey,
		ServerIdentityKey: serverIDKey,
		ServerLogHash:     c.inboundHash.Sum(nil),
		ClientLogHash:     c.outboundHash.Sum(nil),
		ServerLinkCert:    serverLinkCert,
		TLSMasterSecret:   cs.MasterSecret,
		TLSClientRandom:   cs.ClientRandom,
		TLSServerRandom:   cs.ServerRandom,
	}

	err = c.sendCell(a)
	if err != nil {
		return errors.Wrap(err, "failed to send authenticate cell")
	}

	// Send NETINFO cell
	c.sendNetInfoCell()

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

	err := c.sendCell(ourVersionsCell)
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

func (c *Connection) sendNetInfoCell() error {
	netInfoCell, err := NewNetInfoCellFromConn(c.tlsConn)
	if err != nil {
		return errors.Wrap(err, "error initializing net info cell")
	}

	return c.sendCell(netInfoCell)
}

func (c *Connection) sendCell(b CellBuilder) error {
	cell, err := b.Cell(c.proto.CellFormat())
	if err != nil {
		return errors.Wrap(err, "error building cell")
	}

	_, err = c.wr.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send cell")
	}

	c.logger.Debug("sent cell")

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
