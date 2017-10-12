package pearl

// Fingerprint is a relay identity digest (legacy SHA-1).
type Fingerprint [20]byte

func NewFingerprintFromBytes(b []byte) (Fingerprint, error) {
	var fp Fingerprint
	if len(b) != 20 {
		return Fingerprint{}, nil
	}
	copy(fp[:], b)
	return fp, nil
}

// Fingerprinted is something with a fingerprint.
type Fingerprinted interface {
	Fingerprint() (Fingerprint, error)
}
