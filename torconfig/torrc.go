package torconfig

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var ErrTorrcMissingArguments = errors.New("expected arguments in torrc config line")

type optionHandler func(*Config, string) error

var optionHandlers = map[string]optionHandler{
	"orport": orPortHandler,
}

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

func ParseTorrcFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not open torrc")
	}
	defer f.Close()

	return ParseTorrc(f)
}

func orPortHandler(cfg *Config, args string) error {
	port, err := strconv.ParseUint(args, 10, 16)
	if err != nil {
		return err
	}
	cfg.ORPort = uint16(port)
	return nil
}
