package pearl

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"io"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/tls"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
)

// HashedLink keeps a running hash of traffic in either direction. Intended to
// support the handshake process.
type HandshakeLink interface {
	CellSender
	LegacyCellReceiver
	InboundDigest() []byte
	OutboundDigest() []byte
}

type handshakeLink struct {
	CellSender
	LegacyCellReceiver
	inboundHash  hash.Hash
	outboundHash hash.Hash
}

func NewHandshakeLink(rw io.ReadWriter, l log.Logger) HandshakeLink {
	inboundHash := sha256.New()
	outboundHash := sha256.New()
	r := io.TeeReader(rw, inboundHash)
	w := io.MultiWriter(rw, outboundHash)
	return handshakeLink{
		CellSender:         NewCellWriter(w, l),
		LegacyCellReceiver: NewCellReader(r, l),
		inboundHash:        inboundHash,
		outboundHash:       outboundHash,
	}
}

func (l handshakeLink) InboundDigest() []byte {
	return l.inboundHash.Sum(nil)
}

func (l handshakeLink) OutboundDigest() []byte {
	return l.outboundHash.Sum(nil)
}

type Handshake struct {
	Conn        *tls.Conn
	Link        HandshakeLink
	TLSContext  *TLSContext
	IdentityKey *rsa.PublicKey

	PeerFingerprint []byte
	logger          log.Logger
}

func (c *Handshake) Server() error {
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
	certsCell.AddCert(CertTypeLink, c.TLSContext.LinkCert)
	certsCell.AddCert(CertTypeIdentity, c.TLSContext.IDCert)

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

	// Receive CERTS cell
	cell, err := c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	peerCertsCell, err := ParseCertsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse certs cell")
	}

	c.logger.With("numcerts", len(peerCertsCell.Certs)).Debug("received certs cell")

	err = peerCertsCell.ValidateInitiatorRSAOnly()
	if err != nil {
		return errors.Wrap(err, "certs cell failed validation")
	}

	// Form expected AUTHENTICATE values
	clientIdentityKey, err := peerCertsCell.LookupPublicKey(CertTypeIdentity)
	if err != nil {
		return err
	}

	cs := c.Conn.ConnectionState()
	a := AuthRSASHA256TLSSecret{
		ClientIdentityKey: clientIdentityKey,
		ServerIdentityKey: c.IdentityKey,
		ServerLogHash:     c.Link.OutboundDigest(),
		ClientLogHash:     c.Link.InboundDigest(),
		ServerLinkCert:    c.TLSContext.LinkCert.Raw,
		TLSMasterSecret:   cs.MasterSecret,
		TLSClientRandom:   cs.ClientRandom,
		TLSServerRandom:   cs.ServerRandom,
	}

	expectedAuth, err := a.Body()
	if err != nil {
		return err
	}

	// Receive AUTHENTICATE cell
	cell, err = c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	auth, err := ParseAuthenticateCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse authenticate cell")
	}

	if auth.Method != AuthMethodRSASHA256TLSSecret {
		return errors.New("unsupported auth method")
	}

	authPayload, err := NewAuthRSASHA256TLSSecretPayload(auth.Authentication)
	if err != nil {
		return err
	}

	if !bytes.Equal(authPayload.Body(), expectedAuth) {
		return errors.New("unexpected auth payload")
	}

	// TODO(mbm): verify signature
	c.logger.Error("must verify signature in authenticate cell")

	// Send NETINFO
	err = c.sendNetInfoCell()
	if err != nil {
		return errors.Wrap(err, "failed to send net info")
	}

	// Receive NETINFO cell
	cell, err = c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	netInfoCell, err := ParseNetInfoCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse netinfo cell")
	}

	c.logger.With("receiver_addr", netInfoCell.ReceiverAddress).Debug("received net info cell")
	c.logger.Warn("net info processing not implemented")

	return nil
}

func (c *Handshake) Client() error {
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
	cell, err := c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	peerCertsCell, err := ParseCertsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse certs cell")
	}

	c.logger.With("numcerts", len(peerCertsCell.Certs)).Debug("received certs cell")

	cs := c.Conn.ConnectionState()

	err = peerCertsCell.ValidateResponderRSAOnly(cs.PeerCertificates)
	if err != nil {
		return errors.Wrap(err, "certs cell failed validation")
	}

	serverLinkCert, err := peerCertsCell.Lookup(CertTypeLink)
	if err != nil {
		return err
	}

	serverIDCertDER, err := peerCertsCell.Lookup(CertTypeIdentity)
	if err != nil {
		return err
	}

	serverIDKey, err := torcrypto.ParseRSAPublicKeyFromCertificateDER(serverIDCertDER)
	if err != nil {
		return errors.Wrap(err, "failed to extract server identity key")
	}

	c.PeerFingerprint, err = torcrypto.Fingerprint(serverIDKey)
	if err != nil {
		return errors.Wrap(err, "failed to compute server fingerprint")
	}

	// Receive AUTH_CHALLENGE cell
	cell, err = c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	authChallengeCell, err := ParseAuthChallengeCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse auth challenge cell")
	}

	log.WithBytes(c.logger, "challenge", authChallengeCell.Challenge[:]).Debug("received auth challenge cell")

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
	certsCell.AddCert(CertTypeIdentity, c.TLSContext.IDCert)
	certsCell.AddCert(CertTypeAuth, c.TLSContext.AuthCert)

	err = c.sendCell(certsCell)
	if err != nil {
		return errors.Wrap(err, "could not send certs cell")
	}

	// Send AUTHENTICATE
	if !authChallengeCell.SupportsMethod(AuthMethodRSASHA256TLSSecret) {
		return errors.New("server does not support auth method")
	}

	a := &AuthRSASHA256TLSSecret{
		AuthKey:           c.TLSContext.AuthKey,
		ClientIdentityKey: c.IdentityKey,
		ServerIdentityKey: serverIDKey,
		ServerLogHash:     c.Link.InboundDigest(),
		ClientLogHash:     c.Link.OutboundDigest(),
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
	cell, err = c.Link.ReceiveCell()
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}

	netInfoCell, err := ParseNetInfoCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse netinfo cell")
	}

	c.logger.With("receiver_addr", netInfoCell.ReceiverAddress).Debug("received net info cell")
	c.logger.Warn("net info processing not implemented")

	return nil
}

// receiveVersions expects a VERSIONS cell and returns the contained
// LinkProtocolVersions.
func (c *Handshake) receiveVersions() ([]LinkProtocolVersion, error) {
	// Expect a versions cell. Note this has circID length 2 regardless of link
	// protocol version.
	//
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L411-L413
	//
	//	   CIRCID_LEN is 2 for link protocol versions 1, 2, and 3.  CIRCID_LEN
	//	   is 4 for link protocol version 4 or higher.  The VERSIONS cell itself
	//	   always has CIRCID_LEN == 2 for backward compatibility.
	//
	cell, err := c.Link.ReceiveLegacyCell()
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
func (c *Handshake) sendVersions(v []LinkProtocolVersion) error {
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
func (c *Handshake) establishVersion(a, b []LinkProtocolVersion) error {
	proto, err := ResolveVersion(a, b)
	if err != nil {
		return errors.Wrap(err, "could not agree on link protocol version")
	}

	c.logger.With("version", proto).Info("determined link protocol version")

	return nil
}

func (c *Handshake) sendNetInfoCell() error {
	netInfoCell, err := NewNetInfoCellFromConn(c.Conn)
	if err != nil {
		return errors.Wrap(err, "error initializing net info cell")
	}

	return c.sendCell(netInfoCell)
}

// TODO(mbm): kill this function
func (c *Handshake) sendCell(b CellBuilder) error {
	return BuildAndSend(c.Link, b)
}
