package pearl

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L581-L592
//
//	4.2. CERTS cells
//
//	   The CERTS cell describes the keys that a Tor instance is claiming
//	   to have.  It is a variable-length cell.  Its payload format is:
//
//	        N: Number of certs in cell            [1 octet]
//	        N times:
//	           CertType                           [1 octet]
//	           CLEN                               [2 octets]
//	           Certificate                        [CLEN octets]
//
//	   Any extra octets at the end of a CERTS cell MUST be ignored.
//

// CertCellEntry represents one certificate in a CERTS cell.
type CertCellEntry struct {
	Type    CertType
	CertDER []byte
}

// CertsCell is a CERTS cell.
type CertsCell struct {
	Certs []CertCellEntry
}

var _ CellBuilder = new(CertsCell)

func ParseCertsCell(c Cell) (*CertsCell, error) {
	if c.Command() != Certs {
		return nil, ErrUnexpectedCommand
	}

	certs := &CertsCell{}

	p := c.Payload()
	if len(p) < 1 {
		return nil, ErrShortCellPayload
	}

	N := p[0]
	p = p[1:]

	for i := 0; i < int(N); i++ {
		if len(p) < 3 {
			return nil, ErrShortCellPayload
		}
		t := p[0]
		if !IsCertType(t) {
			return nil, errors.New("unrecognized cert type")
		}

		clen := binary.BigEndian.Uint16(p[1:])
		p = p[3:]

		if len(p) < int(clen) {
			return nil, ErrShortCellPayload
		}

		der := p[:clen]
		certs.AddCertDER(CertType(t), der)

		p = p[clen:]
	}

	return certs, nil
}

// AddCert adds a certificate to the cell.
func (c *CertsCell) AddCert(t CertType, crt *x509.Certificate) {
	c.AddCertDER(t, crt.Raw)
}

// AddCertDER adds a DER-encoded certificate to the cell.
func (c *CertsCell) AddCertDER(t CertType, der []byte) {
	c.Certs = append(c.Certs, CertCellEntry{
		Type:    t,
		CertDER: der,
	})
}

// Lookup looks for a certificate of type t in the cell. If found it returns the
// DER-encoded certificate. Otherwise nil.
func (c *CertsCell) Lookup(t CertType) []byte {
	for _, e := range c.Certs {
		if e.Type == t {
			return e.CertDER
		}
	}
	return nil
}

// Cell builds the cell.
func (c CertsCell) Cell() (Cell, error) {
	// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L549-L553
	//
	//	        N: Number of certs in cell            [1 octet]
	//	        N times:
	//	           CertType                           [1 octet]
	//	           CLEN                               [2 octets]
	//	           Certificate                        [CLEN octets]
	//

	length := 1
	N := len(c.Certs)
	encoded := make([][]byte, N)

	for i, entry := range c.Certs {
		encoded[i] = entry.CertDER
		length += 3 + len(entry.CertDER)
	}

	cell := NewCellEmptyPayload(0, Certs, uint16(length))
	payload := cell.Payload()

	payload[0] = byte(N)
	ptr := uint16(1)

	for i, entry := range c.Certs {
		payload[ptr] = byte(entry.Type)
		ptr++

		der := encoded[i]
		clen := uint16(len(der))
		binary.BigEndian.PutUint16(payload[ptr:], clen)
		ptr += 2

		copied := copy(payload[ptr:], der)
		if copied != int(clen) {
			panic("incomplete copy")
		}
		ptr += clen
	}

	return cell, nil
}
