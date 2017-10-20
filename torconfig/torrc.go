package torconfig

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/mmcloughlin/pearl/checked"
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
	"nickname": nicknameHandler,
	"orport":   orPortHandler,
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
	defer checked.MustClose(f)

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
