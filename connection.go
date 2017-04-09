package pearl

import (
	"fmt"
	"net"

	"github.com/mmcloughlin/openssl"
	"github.com/mmcloughlin/pearl/log"
	"github.com/pkg/errors"
)

// Connection encapsulates a router connection.
type Connection struct {
	router     *Router
	conn       net.Conn
	tlsCtx     *TLSContext
	tlsConn    *openssl.Conn
	cellReader CellReader

	logger log.Logger
}

// NewConnection constructs a connection
func NewConnection(r *Router, conn net.Conn, logger log.Logger) (*Connection, error) {
	tlsCtx, err := NewTLSContext(r.IdentityKey())
	if err != nil {
		return nil, err
	}

	tlsConn, err := tlsCtx.ServerConn(conn)
	if err != nil {
		return nil, err
	}

	logger = logger.With("raddr", conn.RemoteAddr())

	return &Connection{
		router:     r,
		conn:       conn,
		tlsCtx:     tlsCtx,
		tlsConn:    tlsConn,
		cellReader: NewCellReader(tlsConn, logger),

		logger: logger,
	}, nil
}

// Handle handles the full lifecycle of the connection.
func (c *Connection) Handle() error {
	c.logger.Info("handle")

	err := c.handshake()
	if err != nil {
		return err
	}

	return nil
}

func (c *Connection) handshake() error {
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
		return errors.Wrap(err, "could not read cell")
	}

	versionsCell, err := ParseVersionsCell(cell)
	if err != nil {
		return errors.Wrap(err, "could not parse versions cell")
	}

	c.logger.With("supported_versions", versionsCell.SupportedVersions).Debug("received versions cell")

	// Send our own versions cell
	ourVersionsCell := VersionsCell{
		SupportedVersions: SupportedLinkProtocolVersions,
	}
	cell, err = ourVersionsCell.Cell(VersionsCellFormat)
	if err != nil {
		return errors.Wrap(err, "error building versions cell")
	}

	_, err = c.tlsConn.Write(cell.Bytes())
	if err != nil {
		return errors.Wrap(err, "could not send versions cell")
	}

	c.logger.With("supported_versions", SupportedLinkProtocolVersions).Debug("sent versions cell")

	// Settle on a protocol version
	proto, err := ResolveVersion(versionsCell.SupportedVersions, ourVersionsCell.SupportedVersions)
	if err != nil {
		return errors.Wrap(err, "could not agree on link protocol version")
	}

	c.logger.With("version", proto).Info("determined link protocol version")
	f := proto.CellFormat()

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

	// XXX
	cell, err = c.cellReader.ReadCell(f)
	if err != nil {
		return errors.Wrap(err, "could not read cell")
	}
	fmt.Println(cell)

	return nil
}
