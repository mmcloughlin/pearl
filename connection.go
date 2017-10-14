package pearl

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net"
	"sync"

	"github.com/mmcloughlin/pearl/tls"
	"github.com/mmcloughlin/pearl/torcrypto"

	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// CellSender can send a Cell.
type CellSender interface {
	SendCell(Cell) error
}

// CellReceiver can receive Cells.
type CellReceiver interface {
	ReceiveCell() (Cell, error)
}

// Link is a Cell communication layer.
type Link interface {
	CellSender
	CellReceiver
}

type link struct {
	CellSender
	CellReceiver
}

func NewLink(s CellSender, r CellReceiver) Link {
	return link{
		CellSender:   s,
		CellReceiver: r,
	}
}

type CellChan chan Cell

func (ch CellChan) SendCell(cell Cell) error {
	ch <- cell
	return nil
}

func (ch CellChan) ReceiveCell() (Cell, error) {
	cell, ok := <-ch
	if !ok {
		return nil, errors.New("closed channel") // XXX correct return?
	}
	return cell, nil
}

type CircuitLink interface {
	CircID() CircID
	Link
}

type circLink struct {
	id CircID
	Link
}

func NewCircuitLink(id CircID, lk Link) CircuitLink {
	return circLink{
		id:   id,
		Link: lk,
	}
}

func (c circLink) CircID() CircID { return c.id }

// Connection encapsulates a router connection.
type Connection struct {
	router      *Router
	tlsCtx      *TLSContext
	tlsConn     *tls.Conn
	fingerprint []byte
	outbound    bool

	proto    LinkProtocolVersion
	channels *ChannelManager

	wr           io.Writer
	rd           io.Reader
	cellReader   CellReceiver
	inboundHash  hash.Hash
	outboundHash hash.Hash

	logger log.Logger
}

var _ CellSender = new(Connection)

// NewServer constructs a server connection.
func NewServer(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ServerConn(conn)
	c := newConnection(r, tlsCtx, tlsConn, logger.With("role", "server"))
	c.outbound = false
	return c, nil
}

// NewClient constructs a client-side connection.
func NewClient(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}
	tlsConn := tlsCtx.ClientConn(conn)
	c := newConnection(r, tlsCtx, tlsConn, logger.With("role", "client"))
	c.outbound = true
	return c, nil
}

func newConnection(r *Router, tlsCtx *TLSContext, tlsConn *tls.Conn, logger log.Logger) *Connection {
	// BUG(mbm): massively inefficient to always hash io (only required for AUTH_CHALLENGE/AUTHENTICATE)
	inboundHash := sha256.New()
	outboundHash := sha256.New()
	rd := io.TeeReader(tlsConn, inboundHash)
	wr := io.MultiWriter(tlsConn, outboundHash)

	return &Connection{
		router:      r,
		tlsCtx:      tlsCtx,
		tlsConn:     tlsConn,
		fingerprint: nil,

		proto:    LinkProtocolNone,
		channels: NewChannelManager(),

		wr:           wr,
		rd:           rd,
		cellReader:   NewCellReader(rd, logger),
		inboundHash:  inboundHash,
		outboundHash: outboundHash,

		logger: log.ForConn(logger, tlsConn),
	}
}

// Fingerprint returns the fingerprint of the connected peer.
func (c *Connection) Fingerprint() (Fingerprint, error) {
	if c.fingerprint == nil {
		return Fingerprint{}, errors.New("peer fingerprint not established")
	}
	return NewFingerprintFromBytes(c.fingerprint)
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

	// Receive CERTS cell
	cell, err := c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	peerCertsCell, err := ParseCertsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse certs cell")
	}

	c.logger.With("numcerts", len(peerCertsCell.Certs)).Debug("received certs cell")
	c.logger.Error("certificate cell verification not implemented")

	// Receive AUTHENTICATE cell
	cell, err = c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	_, err = ParseAuthenticateCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse authenticate cell")
	}
	c.logger.Error("authenticate cell processing not implemented")

	// Receive NETINFO cell
	cell, err = c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	netInfoCell, err := ParseNetInfoCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse netinfo cell")
	}

	c.logger.With("receiver_addr", netInfoCell.ReceiverAddress).Debug("received net info cell")
	c.logger.Error("net info processing not implemented")

	// TODO(mbm): register server connection with router ConnectionManager

	// Enter main loop
	return c.readLoop()
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
	cell, err := c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	peerCertsCell, err := ParseCertsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse certs cell")
	}

	c.logger.With("numcerts", len(peerCertsCell.Certs)).Debug("received certs cell")
	c.logger.Error("certificate cell verification not implemented")

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

	c.fingerprint, err = torcrypto.Fingerprint(serverIDKey)
	if err != nil {
		return errors.Wrap(err, "failed to compute server fingerprint")
	}

	// Receive AUTH_CHALLENGE cell
	cell, err = c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	authChallengeCell, err := ParseAuthChallengeCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse auth challenge cell")
	}

	log.WithBytes(c.logger, "challenge", authChallengeCell.Challenge[:]).Debug("received auth challenge cell")
	c.logger.Error("auth challenge reply not implemented")

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

	// Receive NETINFO cell
	cell, err = c.cellReader.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	netInfoCell, err := ParseNetInfoCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse netinfo cell")
	}

	c.logger.With("receiver_addr", netInfoCell.ReceiverAddress).Debug("received net info cell")
	c.logger.Error("net info processing not implemented")

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
	rd := NewLegacyCellReader(c.rd, c.logger)
	cell, err := rd.ReceiveCell()
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
	cell, err := b.Cell()
	if err != nil {
		return errors.Wrap(err, "error building cell")
	}

	err = c.SendCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not send cell")
	}

	return nil
}

func (c *Connection) SendCell(cell Cell) error {
	_, err := c.wr.Write(cell.Bytes())
	CellLogger(c.logger, cell).Trace("sent cell")
	return err
}

func (c *Connection) readLoop() error {
	var err error
	var cell Cell
	for {
		cell, err = c.cellReader.ReceiveCell()
		if err != nil {
			return errors.Wrap(err, "could not read cell")
		}

		logger := CellLogger(c.logger, cell)
		logger.Trace("received cell")

		switch cell.Command() {
		// Cells to be handled by this Connection
		case Create2:
			Create2Handler(c, cell) // XXX error return
		// Cells related to a circuit
		case Relay:
		case RelayEarly:
			ch, ok := c.channels.Channel(cell.CircID())
			if !ok {
				// BUG(mbm): is logging the correct behavior
				logger.Error("unrecognized circ id")
				continue
			}
			ch <- cell
		// Cells to be ignored
		case Padding:
		case Vpadding:
			logger.Debug("skipping padding cell")
		// Something which shouldn't happen
		default:
			logger.Error("no handler registered")
		}
	}
}

// GenerateCircuitLink
func (c *Connection) GenerateCircuitLink() CircuitLink {
	// BUG(mbm): what if c.proto has not been established
	id, ch := c.channels.New(c.outbound)
	return NewCircuitLink(id, NewLink(c, CellChan(ch)))
}

// NewCircuitLink
func (c *Connection) NewCircuitLink(id CircID) (CircuitLink, error) {
	ch, err := c.channels.NewWithID(id)
	if err != nil {
		return nil, err
	}
	return NewCircuitLink(id, NewLink(c, CellChan(ch))), nil
}

func CellLogger(l log.Logger, cell Cell) log.Logger {
	return l.With("cmd", cell.Command()).
		With("circid", cell.CircID()).
		With("bytes", hex.EncodeToString(cell.Bytes()))
}

// ChannelManager manages a collection of cell channels.
type ChannelManager struct {
	channels map[CircID]chan Cell

	sync.RWMutex
}

func NewChannelManager() *ChannelManager {
	return &ChannelManager{
		channels: make(map[CircID]chan Cell),
	}
}

func (m *ChannelManager) New(outbound bool) (CircID, chan Cell) {
	m.Lock()
	defer m.Unlock()

	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L931-L933
	//
	//	   In link protocol version 4 or higher, whichever node initiated the
	//	   connection sets its MSB to 1, and whichever node didn't initiate the
	//	   connection sets its MSB to 0.
	//
	msb := uint32(0)
	if outbound {
		msb = uint32(1)
	}

	// BUG(mbm): potential infinite (or at least long) loop to find a new id
	for {
		id := GenerateCircID(msb)
		// 0 is reserved
		if id == 0 {
			continue
		}
		_, exists := m.channels[id]
		if exists {
			continue
		}
		ch := m.newWithID(id)
		return id, ch
	}
}

func (m *ChannelManager) NewWithID(id CircID) (chan Cell, error) {
	m.Lock()
	defer m.Unlock()
	_, exists := m.channels[id]
	if exists {
		return nil, errors.New("cannot override existing channel id")
	}
	return m.newWithID(id), nil
}

func (m *ChannelManager) newWithID(id CircID) chan Cell {
	ch := make(chan Cell)
	m.channels[id] = ch
	return ch
}

func (m *ChannelManager) Channel(id CircID) (chan Cell, bool) {
	m.RLock()
	defer m.RUnlock()
	ch, ok := m.channels[id]
	return ch, ok
}
