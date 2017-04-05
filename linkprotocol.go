package pearl

import "errors"

// LinkProtocolVersion represents the version number of the link protocol.
type LinkProtocolVersion uint16

var (
	// LinkProtocolNone is an empty placeholder value for the
	// LinkProtocolVersion type.
	LinkProtocolNone LinkProtocolVersion
)

// ErrNoCommonVersion is returned from ResolveVersion when the two lists of
// supported versions do not have any versions in common.
var ErrNoCommonVersion = errors.New("no common version found")

// ResolveVersion determines the agreed link protocol given the lists
// supported by each side. This is the max in both sides.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L521-L527
//
//	   The payload in a VERSIONS cell is a series of big-endian two-byte
//	   integers.  Both parties MUST select as the link protocol version the
//	   highest number contained both in the VERSIONS cell they sent and in the
//	   versions cell they received.  If they have no such version in common,
//	   they cannot communicate and MUST close the connection.  Either party MUST
//	   close the connection if the versions cell is not well-formed (for example,
//	   if it contains an odd number of bytes).
//
func ResolveVersion(a, b []LinkProtocolVersion) (LinkProtocolVersion, error) {
	supportedByA := map[LinkProtocolVersion]bool{}
	for _, v := range a {
		supportedByA[v] = true
	}

	max := LinkProtocolNone
	for _, v := range b {
		_, mutual := supportedByA[v]
		if mutual && v > max {
			max = v
		}
	}

	if max == LinkProtocolNone {
		return LinkProtocolNone, ErrNoCommonVersion
	}

	return max, nil
}
