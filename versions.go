package pearl

import (
	"encoding/binary"
	"errors"
)

// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L501-L541
//
//	4.1. Negotiating versions with VERSIONS cells
//
//	   There are multiple instances of the Tor link connection protocol.  Any
//	   connection negotiated using the "certificates up front" handshake (see
//	   section 2 above) is "version 1".  In any connection where both parties
//	   have behaved as in the "renegotiation" handshake, the link protocol
//	   version must be 2.  In any connection where both parties have behaved
//	   as in the "in-protocol" handshake, the link protocol must be 3 or higher.
//
//	   To determine the version, in any connection where the "renegotiation"
//	   or "in-protocol" handshake was used (that is, where the responder
//	   sent only one certificate at first and where the initiator did not
//	   send any certificates in the first negotiation), both parties MUST
//	   send a VERSIONS cell.  In "renegotiation", they send a VERSIONS cell
//	   right after the renegotiation is finished, before any other cells are
//	   sent.  In "in-protocol", the initiator sends a VERSIONS cell
//	   immediately after the initial TLS handshake, and the responder
//	   replies immediately with a VERSIONS cell.  Parties MUST NOT send any
//	   other cells on a connection until they have received a VERSIONS cell.
//
//	   The payload in a VERSIONS cell is a series of big-endian two-byte
//	   integers.  Both parties MUST select as the link protocol version the
//	   highest number contained both in the VERSIONS cell they sent and in the
//	   versions cell they received.  If they have no such version in common,
//	   they cannot communicate and MUST close the connection.  Either party MUST
//	   close the connection if the versions cell is not well-formed (for example,
//	   if it contains an odd number of bytes).
//
//	   Since the version 1 link protocol does not use the "renegotiation"
//	   handshake, implementations MUST NOT list version 1 in their VERSIONS
//	   cell.  When the "renegotiation" handshake is used, implementations
//	   MUST list only the version 2.  When the "in-protocol" handshake is
//	   used, implementations MUST NOT list any version before 3, and SHOULD
//	   list at least version 3.
//
//	   Link protocols differences are:
//	     1 -- The "certs up front" handshake.
//	     2 -- Uses the renegotiation-based handshake. Introduces
//	          variable-length cells.
//	     3 -- Uses the in-protocol handshake.
//	     4 -- Increases circuit ID width to 4 bytes.
//

var ErrVersionsCellOddLength = errors.New("versions cell with odd length")

type VersionsCell struct {
	SupportedVersions []LinkProtocolVersion
}

func ParseVersionsCell(c Cell) (*VersionsCell, error) {
	if c.Command() != Versions {
		return nil, ErrUnexpectedCommand
	}

	payload := c.Payload()
	n := len(payload)

	if (n % 2) != 0 {
		return nil, ErrVersionsCellOddLength
	}

	v := make([]LinkProtocolVersion, n/2)
	for i := 0; i < n; i += 2 {
		v[i/2] = LinkProtocolVersion(binary.BigEndian.Uint16(payload[i : i+2]))
	}

	return &VersionsCell{
		SupportedVersions: v,
	}, nil
}

func (v VersionsCell) Cell() Cell {
	n := uint16(2 * len(v.SupportedVersions))
	c := NewCellEmptyPayload(VersionsCellFormat, 0, Versions, n)
	payload := c.Payload()
	for i, version := range v.SupportedVersions {
		binary.BigEndian.PutUint16(payload[2*i:2*i+2], uint16(version))
	}
	return c
}
