// Package meta provides versioning information.
package meta

const placeholder = "unknown"

// Git SHA of the build (full and abbreviated). Populated at build time.
var (
	GitSHAFull = placeholder
	GitSHA     = placeholder
)

// Populated returns whether version information has been populated.
func Populated() bool {
	return GitSHA != placeholder
}
