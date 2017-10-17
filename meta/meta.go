// Package meta provides versioning information.
package meta

import (
	"github.com/mmcloughlin/pearl/protover"
	"github.com/mmcloughlin/pearl/torconfig"
)

const placeholder = "unknown"

// Git SHA of the build (full and abbreviated). Populated at build time.
var (
	GitSHAFull = placeholder
	GitSHA     = placeholder
)

// Populated returns whether build information has been populated.
func Populated() bool {
	return GitSHA != placeholder
}

// Platform is a "platform" string identifying this Tor implementation.
var Platform = torconfig.NewPlatformHostOS("Pearl", GitSHA)

// Protocols defines the sub-protocols we support.
var Protocols = protover.SupportedProtocols{
	protover.Link: []protover.VersionRange{
		protover.SingleVersion(4),
	},
	protover.LinkAuth: []protover.VersionRange{
		protover.SingleVersion(1),
	},
	protover.Relay: []protover.VersionRange{
		protover.SingleVersion(2),
	},
}
