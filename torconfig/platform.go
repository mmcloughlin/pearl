package torconfig

import (
	"fmt"
	"runtime"
	"strings"
)

type Platform struct {
	Software string
	Version  string
	OS       string
}

func NewPlatform(software, version, os string) Platform {
	return Platform{
		Software: software,
		Version:  version,
		OS:       os,
	}
}

func NewPlatformHostOS(software, version string) Platform {
	return NewPlatform(software, version, runtime.GOOS)
}

func (p Platform) String() string {
	return fmt.Sprintf("%s %s on %s", p.Software, p.Version, strings.Title(p.OS))
}
