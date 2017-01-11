package tordir

import (
	"errors"
	"net"
	"regexp"
	"strconv"
)

// Potential errors when constructing a server descriptor.
var (
	ErrServerDescriptorBadNickname   = errors.New("invalid nickname")
	ErrServerDescriptorNotIPv4       = errors.New("require ipv4 address")
	ErrServerDescriptorMissingRouter = errors.New("missing router keyword")
)

// ServerDescriptor is a builder for a server descriptor to be published to
// directory servers.
type ServerDescriptor struct {
	router *Item
	items  []*Item
}

// NewServerDescriptor constructs an empty server descriptor.
func NewServerDescriptor() *ServerDescriptor {
	return &ServerDescriptor{
		items: make([]*Item, 0),
	}
}

// XXX cite
var nicknameRx = regexp.MustCompile(`^[[:alnum:]]{1,19}$`)

// SetRouter sets the router description. This is required.
// XXX cite
func (d *ServerDescriptor) SetRouter(nickname string, addr net.IP, orPort, dirPort uint16) error {
	if !nicknameRx.MatchString(nickname) {
		return ErrServerDescriptorBadNickname
	}

	addr = addr.To4()
	if addr == nil {
		return ErrServerDescriptorNotIPv4
	}

	args := []string{
		nickname,
		addr.String(),
		strconv.FormatUint(uint64(orPort), 10),
		"0", // SOCKSPort
		strconv.FormatUint(uint64(dirPort), 10),
	}
	d.router = NewItem("router", args)
	return nil
}

// Validate checks whether the descriptor is valid.
func (d *ServerDescriptor) Validate() error {
	if d.router == nil {
		return ErrServerDescriptorMissingRouter
	}
	return nil
}

// Document generates the Document for this descriptor.
func (d *ServerDescriptor) Document() (*Document, error) {
	err := d.Validate()
	if err != nil {
		return nil, err
	}

	doc := &Document{}
	doc.AddItem(d.router)
	for _, item := range d.items {
		doc.AddItem(item)
	}
	return doc, nil
}
