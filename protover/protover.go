// Package protover implements types for protocol version strings.
package protover

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Reference: https://github.com/torproject/torspec/blob/f66d1826c0b32d307898bba081dbf8ef598d4037/tor-spec.txt#L1842-L1854
//
//	   Starting in version 0.2.9.4-alpha, the initial required protocols for
//	   clients that we will Recommend and Require are:
//
//	      Cons=1-2 Desc=1-2 DirCache=1 HSDir=2 HSIntro=3 HSRend=1 Link=4
//	      LinkAuth=1 Microdesc=1-2 Relay=2
//
//	   For relays we will Require:
//
//	      Cons=1 Desc=1 DirCache=1 HSDir=2 HSIntro=3 HSRend=1 Link=3-4
//	      LinkAuth=1 Microdesc=1 Relay=1-2
//
//	   For relays, we will additionally Recommend all protocols which we
//	   recommend for clients.
//

// Expectations for client and relay implementations.
var (
	ClientRequired = SupportedProtocols{
		Cons:      {NewVersionRange(1, 2)},
		Desc:      {NewVersionRange(1, 2)},
		DirCache:  {SingleVersion(1)},
		HSDir:     {SingleVersion(2)},
		HSIntro:   {SingleVersion(3)},
		HSRend:    {SingleVersion(1)},
		Link:      {SingleVersion(4)},
		LinkAuth:  {SingleVersion(1)},
		Microdesc: {NewVersionRange(1, 2)},
		Relay:     {SingleVersion(2)},
	}
	ClientRecommended = ClientRequired

	RelayRequired = SupportedProtocols{
		Cons:      {SingleVersion(1)},
		Desc:      {SingleVersion(1)},
		DirCache:  {SingleVersion(1)},
		HSDir:     {SingleVersion(2)},
		HSIntro:   {SingleVersion(3)},
		HSRend:    {SingleVersion(1)},
		Link:      {NewVersionRange(3, 4)},
		LinkAuth:  {SingleVersion(1)},
		Microdesc: {SingleVersion(1)},
		Relay:     {NewVersionRange(1, 2)},
	}
	RelayRecommended = ClientRecommended
)

// Reference: https://github.com/torproject/tor/blob/d8604b8729b24f964d78d188b89493098d3eb92b/src/or/protover.c#L34-L49
//
//	/** Mapping between protocol type string and protocol type. */
//	static const struct {
//	  protocol_type_t protover_type;
//	  const char *name;
//	} PROTOCOL_NAMES[] = {
//	  { PRT_LINK, "Link" },
//	  { PRT_LINKAUTH, "LinkAuth" },
//	  { PRT_RELAY, "Relay" },
//	  { PRT_DIRCACHE, "DirCache" },
//	  { PRT_HSDIR, "HSDir" },
//	  { PRT_HSINTRO, "HSIntro" },
//	  { PRT_HSREND, "HSRend" },
//	  { PRT_DESC, "Desc" },
//	  { PRT_MICRODESC, "Microdesc"},
//	  { PRT_CONS, "Cons" }
//	};
//

// ProtocolName is the name for a subset of the Tor protocol.
type ProtocolName string

// Recognized protocol names.
const (
	Link      ProtocolName = "Link"
	LinkAuth  ProtocolName = "LinkAuth"
	Relay     ProtocolName = "Relay"
	DirCache  ProtocolName = "DirCache"
	HSDir     ProtocolName = "HSDir"
	HSIntro   ProtocolName = "HSIntro"
	HSRend    ProtocolName = "HSRend"
	Desc      ProtocolName = "Desc"
	Microdesc ProtocolName = "Microdesc"
	Cons      ProtocolName = "Cons"
)

// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/dir-spec.txt#L774-L798
//
//	   "proto" SP Entries NL
//
//	       [At most one.]
//
//	       Entries =
//	       Entries = Entry
//	       Entries = Entry SP Entries
//
//	       Entry = Keyword "=" Values
//
//	       Values = Value
//	       Values = Value "," Values
//
//	       Value = Int
//	       Value = Int "-" Int
//
//	       Int = NON_ZERO_DIGIT
//	       Int = Int DIGIT
//
//	       Each 'Entry' in the "proto" line indicates that the Tor relay supports
//	       one or more versions of the protocol in question.  Entries should be
//	       sorted by keyword.  Values should be numerically ascending within each
//	       entry.  (This implies that there should be no overlapping ranges.)
//	       Ranges should be represented as compactly as possible. Ints must be no
//	       more than 2^32 - 1.
//

type VersionRange struct {
	low  int
	high int
}

func SingleVersion(v int) VersionRange {
	return VersionRange{
		low:  v,
		high: v,
	}
}

func NewVersionRange(l, h int) VersionRange {
	if h < l {
		panic("bad range")
	}
	return VersionRange{
		low:  l,
		high: h,
	}
}

func (v VersionRange) String() string {
	if v.high < v.low {
		panic("bad range")
	}
	if v.low == v.high {
		return strconv.Itoa(v.low)
	}
	return fmt.Sprintf("%d-%d", v.low, v.high)
}

type SupportedProtocols map[ProtocolName][]VersionRange

func New() SupportedProtocols {
	return make(SupportedProtocols)
}

func (s SupportedProtocols) Supports(n ProtocolName, v VersionRange) {
	_, ok := s[n]
	if !ok {
		s[n] = nil
	}
	s[n] = append(s[n], v)
}

func (s SupportedProtocols) Strings() []string {
	var parts []string
	for n, ranges := range s {
		parts = append(parts, string(n)+"="+versionRangesString(ranges))
	}
	sort.Strings(parts)
	return parts
}

func (s SupportedProtocols) String() string {
	return strings.Join(s.Strings(), " ")
}

func versionRangesString(ranges []VersionRange) string {
	var parts []string
	for _, v := range ranges {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ",")
}
