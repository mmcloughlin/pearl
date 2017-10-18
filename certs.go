package pearl

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"time"

	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/pkg/errors"
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

// CountType returns the number of certificates in the cell of the given type.
func (c *CertsCell) CountType(t CertType) int {
	n := 0
	for _, e := range c.Certs {
		if e.Type == t {
			n++
		}
	}
	return n
}

// Search looks for a certificate of type t in the cell. If found it returns the
// DER-encoded certificate. Errors if there are multiple certificates of that type.
// Returns nil if there is no such certificate.
func (c *CertsCell) Search(t CertType) ([]byte, error) {
	if c.CountType(t) > 1 {
		return nil, errors.New("multiple certificates of same type")
	}
	for _, e := range c.Certs {
		if e.Type == t {
			return e.CertDER, nil
		}
	}
	return nil, nil
}

// Lookup is like Search except it will error if there is no such certificate.
func (c *CertsCell) Lookup(t CertType) ([]byte, error) {
	der, err := c.Search(t)
	if err != nil {
		return nil, err
	}
	if der == nil {
		return nil, errors.New("missing certificate")
	}
	return der, nil
}

// LookupX509 is like Lookup except it also parses the certificate as X509.
func (c *CertsCell) LookupX509(t CertType) (*x509.Certificate, error) {
	der, err := c.Lookup(t)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// LookupPublicKey is like Lookup but it returns only the public key.
func (c *CertsCell) LookupPublicKey(t CertType) (*rsa.PublicKey, error) {
	der, err := c.Lookup(t)
	if err != nil {
		return nil, err
	}
	return torcrypto.ParseRSAPublicKeyFromCertificateDER(der)
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

// ValidateResponderRSAOnly checks whether the certificate cell matches
// requirements for a responder. Requires the TLS peer certiciates for comparison.
func (c *CertsCell) ValidateResponderRSAOnly(peerCerts []*x509.Certificate) error {
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L635-L648
	//
	//	   To authenticate the responder as having a given RSA identity only,
	//	   the initiator MUST check the following:
	//	     * The CERTS cell contains exactly one CertType 1 "Link" certificate.
	//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	//	     * Both certificates have validAfter and validUntil dates that
	//	       are not expired.
	//	     * The certified key in the Link certificate matches the
	//	       link key that was used to negotiate the TLS connection.
	//	     * The certified key in the ID certificate is a 1024-bit RSA key.
	//	     * The certified key in the ID certificate was used to sign both
	//	       certificates.
	//	     * The link certificate is correctly signed with the key in the
	//	       ID certificate
	//	     * The ID certificate is correctly self-signed.
	//
	// Reference: https://github.com/torproject/tor/blob/b9b5f9a1a5a683611789ffe4c49e41325102cabc/src/or/torcert.c#L493-L502
	//
	//	  if (certs->started_here) {
	//	    if (! (id_cert && link_cert))
	//	      ERR("The certs we wanted (ID, Link) were missing");
	//	    if (! tor_tls_cert_matches_key(tls, link_cert))
	//	      ERR("The link certificate didn't match the TLS public key");
	//	    if (! tor_tls_cert_is_valid(severity, link_cert, id_cert, now, 0))
	//	      ERR("The link certificate was not valid");
	//	    if (! tor_tls_cert_is_valid(severity, id_cert, id_cert, now, 1))
	//	      ERR("The ID certificate was not valid");
	//	  } else {
	//

	link, err := c.LookupX509(CertTypeLink)
	if err != nil {
		return err
	}

	ident, err := c.LookupX509(CertTypeIdentity)
	if err != nil {
		return err
	}

	if err := certificateChecks(link, ident, time.Now(), false); err != nil {
		return err
	}

	if err := certificateChecks(ident, ident, time.Now(), true); err != nil {
		return err
	}

	if len(peerCerts) != 1 {
		return errors.New("expecting 1 TLS peer certificate")
	}

	tlsKey, err := torcrypto.ExtractRSAPublicKeyFromCertificate(peerCerts[0])
	if err != nil {
		return errors.New("could not extract RSA key from peer certificate")
	}

	linkKey, err := torcrypto.ExtractRSAPublicKeyFromCertificate(link)
	if err != nil {
		return errors.New("could not extract RSA key from link certificate")
	}

	if !torcrypto.RSAPublicKeysEqual(tlsKey, linkKey) {
		return errors.New("link certificate does not match TLS certificate")
	}

	return nil
}

func (c *CertsCell) ValidateInitiatorRSAOnly() error {
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/tor-spec.txt#L678-L693
	//
	//	   To authenticate the initiator as having an RSA identity key only,
	//	   the responder MUST check the following:
	//	     * The CERTS cell contains exactly one CertType 3 "AUTH" certificate.
	//	     * The CERTS cell contains exactly one CertType 2 "ID" certificate.
	//	     * Both certificates have validAfter and validUntil dates that
	//	       are not expired.
	//	     * The certified key in the AUTH certificate is a 1024-bit RSA key.
	//	     * The certified key in the ID certificate is a 1024-bit RSA key.
	//	     * The certified key in the ID certificate was used to sign both
	//	       certificates.
	//	     * The auth certificate is correctly signed with the key in the
	//	       ID certificate.
	//	     * The ID certificate is correctly self-signed.
	//	   Checking these conditions is NOT sufficient to authenticate that the
	//	   initiator has the ID it claims; to do so, the cells in 4.3 and 4.4
	//	   below must be exchanged.
	//
	// Reference: https://github.com/torproject/tor/blob/b9b5f9a1a5a683611789ffe4c49e41325102cabc/src/or/torcert.c#L503-L508
	//
	//	    if (! (id_cert && auth_cert))
	//	      ERR("The certs we wanted (ID, Auth) were missing");
	//	    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, auth_cert, id_cert, now, 1))
	//	      ERR("The authentication certificate was not valid");
	//	    if (! tor_tls_cert_is_valid(LOG_PROTOCOL_WARN, id_cert, id_cert, now, 1))
	//	      ERR("The ID certificate was not valid");
	//

	auth, err := c.LookupX509(CertTypeAuth)
	if err != nil {
		return err
	}

	ident, err := c.LookupX509(CertTypeIdentity)
	if err != nil {
		return err
	}

	if err = certificateChecks(auth, ident, time.Now(), true); err != nil {
		return err
	}

	if err = certificateChecks(ident, ident, time.Now(), true); err != nil {
		return err
	}

	return nil
}

func certificateChecks(crt *x509.Certificate, parent *x509.Certificate, t time.Time, require1024 bool) error {
	if !validCertificateDates(crt, t) {
		return errors.New("outside certificate validity period")
	}

	k, err := torcrypto.ExtractRSAPublicKeyFromCertificate(crt)
	if err != nil {
		return err
	}

	if require1024 && torcrypto.RSAPublicKeySize(k) != 1024 {
		return errors.New("expect 1024-bit RSA key")
	}

	err = parent.CheckSignature(crt.SignatureAlgorithm, crt.RawTBSCertificate, crt.Signature)
	if err != nil {
		return errors.Wrap(err, "certificate signature failed")
	}

	return nil
}

// validCertificateDates checks whether t is inside the validity period of the
// certificate.
func validCertificateDates(crt *x509.Certificate, t time.Time) bool {
	return !t.After(crt.NotAfter) && !t.Before(crt.NotBefore)
}
