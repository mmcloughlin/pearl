package pearl

import (
	"encoding/binary"
	"errors"
	"net"
)

// Reference: https://github.com/torproject/torspec/blob/8aaa36d1a062b20ca263b6ac613b77a3ba1eb113/tor-spec.txt#L944-L952
//
//	   An EXTEND2 cell's relay payload contains:
//	       NSPEC      (Number of link specifiers)     [1 byte]
//	         NSPEC times:
//	           LSTYPE (Link specifier type)           [1 byte]
//	           LSLEN  (Link specifier length)         [1 byte]
//	           LSPEC  (Link specifier)                [LSLEN bytes]
//	       HTYPE      (Client Handshake Type)         [2 bytes]
//	       HLEN       (Client Handshake Data Len)     [2 bytes]
//	       HDATA      (Client Handshake Data)         [HLEN bytes]
//

type LinkSpec struct {
	Type LinkSpecType
	Spec []byte
}

func NewLinkSpecTCP(ip net.IP, port uint16) LinkSpec {
	s := LinkSpec{}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	if ip4 := ip.To4(); ip4 != nil {
		s.Type = LinkSpecTLSTCPIPv4
		s.Spec = append(ip4, portBytes...)
		return s
	}
	if ip6 := ip.To16(); ip6 != nil {
		s.Type = LinkSpecTLSTCPIPv6
		s.Spec = append(ip6, portBytes...)
		return s
	}
	panic("unrecognized ip type")
}

func NewLinkSpecLegacyID(id []byte) LinkSpec {
	if len(id) != 20 {
		panic("wrong length")
	}
	return LinkSpec{
		Type: LinkSpecLegacyIdentity,
		Spec: id,
	}
}

// Address converts the LinkSpec into an address. Returns nil if that is not
// possible, for example in the case of LinkSpecLegacyIdentity or
// LinkSpecEd25519Identity.
func (s LinkSpec) Address() (net.Addr, error) {
	n := 0
	switch s.Type {
	case LinkSpecTLSTCPIPv4:
		n = 4
	case LinkSpecTLSTCPIPv6:
		n = 16
	default:
		return nil, nil
	}
	if len(s.Spec) != n+2 {
		return nil, errors.New("bad spec length")
	}
	return &net.TCPAddr{
		IP:   net.IP(s.Spec[:n]),
		Port: int(binary.BigEndian.Uint16(s.Spec[n:])),
	}, nil
}

type Extend2Payload struct {
	LinkSpecs     []LinkSpec
	HandshakeData []byte
}

var _ ConnectionHint = new(Extend2Payload)

func (e *Extend2Payload) UnmarshalBinary(p []byte) error {
	if len(p) < 1 {
		return ErrShortCellPayload
	}

	nspec, p := int(p[0]), p[1:]
	e.LinkSpecs = make([]LinkSpec, nspec)

	for i := 0; i < nspec; i++ {
		if len(p) < 2 {
			return ErrShortCellPayload
		}
		lstype := p[0]
		if !IsLinkSpecType(lstype) {
			return errors.New("unrecognized link spec type")
		}
		lslen := int(p[1])
		p = p[2:]

		if len(p) < lslen {
			return ErrShortCellPayload
		}
		lspec := p[:lslen]
		p = p[lslen:]

		e.LinkSpecs[i] = LinkSpec{
			Type: LinkSpecType(lstype),
			Spec: lspec,
		}
	}

	e.HandshakeData = p

	return nil
}

func (e *Extend2Payload) Fingerprint() (Fingerprint, error) {
	for _, ls := range e.LinkSpecs {
		if ls.Type == LinkSpecLegacyIdentity {
			return NewFingerprintFromBytes(ls.Spec)
		}
	}
	return Fingerprint{}, errors.New("no fingerprint provided in extend cell")
}

func (e *Extend2Payload) Addresses() ([]net.Addr, error) {
	var addrs []net.Addr
	for _, ls := range e.LinkSpecs {
		addr, err := ls.Address()
		if err != nil {
			return nil, err
		}
		if addr != nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}
