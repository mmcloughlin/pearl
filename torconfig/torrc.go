package torconfig

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mmcloughlin/pearl/check"
	"github.com/pkg/errors"
)

// ErrTorrcMissingArguments occurs if the parser finds a config line without
// arguments. Expect to see a keyword followed by one or more arguments.
var ErrTorrcMissingArguments = errors.New("expected arguments in torrc config line")

// optionHandler is a function that can populate/modify the passed config
// struct based on string argument(s).
type optionHandler func(*Config, string) error

// optionHandlers is a map from keywords (lowercased) to the associated
// handler. Used by ParseTorrc.
var optionHandlers = map[string]optionHandler{
	"nickname":       nicknameHandler,
	"orport":         orPortHandler,
	"contactinfo":    contactInfoHandler,
	"address":        addressHandler,
	"bandwidthrate":  bandwidthRateHandler,
	"bandwidthburst": bandwidthBurstHandler,
}

// ParseTorrc parses Config from the given reader (in torrc format).
func ParseTorrc(r io.Reader) (*Config, error) {
	cfg := &Config{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// skip blanks and comments
		if line == "" {
			continue
		}
		if line[0] == '#' {
			continue
		}

		// parse out keywords and arguments
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return nil, ErrTorrcMissingArguments
		}
		keyword := strings.ToLower(parts[0])
		args := parts[1]

		// pass to handler, if any
		handler, ok := optionHandlers[keyword]
		if !ok {
			continue
		}

		err := handler(cfg, args)
		if err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ParseTorrcFile parses config from the given torrc file.
func ParseTorrcFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not open torrc")
	}
	defer check.MustClose(f)

	return ParseTorrc(f)
}

// nicknameHandler parses the "Nickname" line.
func nicknameHandler(cfg *Config, args string) error {
	cfg.Nickname = args
	return nil
}

// orPortHandler parses the "OrPort" line.
func orPortHandler(cfg *Config, args string) error {
	port, err := strconv.ParseUint(args, 10, 16)
	if err != nil {
		return err
	}
	cfg.ORPort = uint16(port)
	return nil
}

// addressHandler parses the "Address" line as an IP address.
func addressHandler(cfg *Config, args string) error {
	ip := net.ParseIP(args)
	if ip == nil {
		return errors.New("could not parse IP")
	}
	cfg.IP = ip
	return nil
}

// contactInfoHandler parses the "ContactInfo" line.
func contactInfoHandler(cfg *Config, args string) error {
	cfg.Contact = args
	return nil
}

// bandwidthRateHandler parses the "BandwidthRate" line.
func bandwidthRateHandler(cfg *Config, args string) (err error) {
	cfg.BandwidthAverage, err = parseBytes(args)
	return
}

// bandwidthBurstHandler parses the "BandwidthBurst" line.
func bandwidthBurstHandler(cfg *Config, args string) (err error) {
	cfg.BandwidthBurst, err = parseBytes(args)
	return
}

// parseBytes parses a string as a number of bytes.
func parseBytes(s string) (int, error) {
	parts := strings.Split(s, " ")
	if len(parts) < 2 {
		return 0, errors.New("expected number and unit")
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	unit := strings.ToLower(parts[1])
	multBits, ok := unitToBits[unit]
	if !ok {
		return 0, errors.New("unknown unit")
	}
	return (n * multBits) / 8, nil
}

// Reference: https://github.com/torproject/tor/blob/e5c341eb7c1189985d903f708ce91516da7f0c76/doc/tor.1.txt#L208-L216
//
//	    With this option, and in other options that take arguments in bytes,
//	    KBytes, and so on, other formats are also supported. Notably, "KBytes" can
//	    also be written as "kilobytes" or "kb"; "MBytes" can be written as
//	    "megabytes" or "MB"; "kbits" can be written as "kilobits"; and so forth.
//	    Tor also accepts "byte" and "bit" in the singular.
//	    The prefixes "tera" and "T" are also recognized.
//	    If no units are given, we default to bytes.
//	    To avoid confusion, we recommend writing "bytes" or "bits" explicitly,
//	    since it's easy to forget that "B" means bytes, not bits.
//
var unitToBits = map[string]int{
	"bytes":     8,
	"bits":      1,
	"kb":        8192,
	"kbytes":    8192,
	"kilobytes": 8192,
	"kbits":     1024,
	"kilobits":  1024,
	"mb":        8388608,
	"mbytes":    8388608,
	"megabytes": 8388608,
	"mbits":     1048576,
	"megabits":  1048576,
	"gb":        8589934592,
	"gbytes":    8589934592,
	"gigabytes": 8589934592,
	"gbits":     1073741824,
	"gigabits":  1073741824,
	"tb":        8796093022208,
	"tbytes":    8796093022208,
	"terabytes": 8796093022208,
	"tbits":     1099511627776,
	"terabits":  1099511627776,
}
