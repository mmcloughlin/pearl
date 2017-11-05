package torconfig

import (
	"fmt"
	"runtime"
	"strings"
)

// Platform encapsulates a standard specification of the platform a router is
// using. This specifies which software it is running, the version of that
// software and the host OS.
type Platform struct {
	Software string
	Version  string
	OS       string
}

// NewPlatform constructs a new Platform specification.
func NewPlatform(software, version, os string) Platform {
	return Platform{
		Software: software,
		Version:  version,
		OS:       os,
	}
}

// NewPlatformHostOS constructs a new Platform object with the operating
// system field set to the current host OS.
func NewPlatformHostOS(software, version string) Platform {
	return NewPlatform(software, version, runtime.GOOS)
}

// NewOfficialPlatform constructs a new Platform object for official Tor of the
// given version.
func NewOfficialPlatform(version string) Platform {
	return NewPlatformHostOS("Tor", version)
}

// String converts Platform to the standard string representation seen in
// server descriptors.
func (p Platform) String() string {
	return fmt.Sprintf("%s %s on %s", p.Software, p.Version, strings.Title(p.OS))
}
