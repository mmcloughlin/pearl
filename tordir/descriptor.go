package tordir

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

const (
	routerKeyword    = "router"
	bandwidthKeyword = "bandwidth"
	publishedKeyword = "published"
)

var requiredKeywords = []string{
	routerKeyword,
	bandwidthKeyword,
	publishedKeyword,
}

// Potential errors when constructing a server descriptor.
var (
	ErrServerDescriptorBadNickname = errors.New("invalid nickname")
	ErrServerDescriptorNotIPv4     = errors.New("require ipv4 address")
)

// ServerDescriptorMissingFieldError indicates that a required field is
// missing from a server descriptor.
type ServerDescriptorMissingFieldError string

func (e ServerDescriptorMissingFieldError) Error() string {
	return fmt.Sprintf("missing field '%s'", string(e))
}

// ServerDescriptor is a builder for a server descriptor to be published to
// directory servers.
type ServerDescriptor struct {
	router   *Item
	items    []*Item
	keywords map[string]bool
}

// NewServerDescriptor constructs an empty server descriptor.
func NewServerDescriptor() *ServerDescriptor {
	return &ServerDescriptor{
		items:    make([]*Item, 0),
		keywords: make(map[string]bool),
	}
}

func (d *ServerDescriptor) addItem(item *Item) {
	d.items = append(d.items, item)
	d.keywords[item.Keyword] = true
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
	d.router = NewItem(routerKeyword, args)
	d.keywords[routerKeyword] = true
	return nil
}

// SetBandwidth sets the bandwidth of the server.
// XXX cite
func (d *ServerDescriptor) SetBandwidth(avg, burst, observed int) error {
	args := []string{
		strconv.Itoa(avg),
		strconv.Itoa(burst),
		strconv.Itoa(observed),
	}
	d.addItem(NewItem(bandwidthKeyword, args))
	return nil
}

// SetPublishedTime sets the time the descriptor was published.
// XXX cite
func (d *ServerDescriptor) SetPublishedTime(t time.Time) error {
	args := []string{
		t.In(time.UTC).Format("2006-01-02 15:04:05"),
	}
	d.addItem(NewItem(publishedKeyword, args))
	return nil
}

// Validate checks whether the descriptor is valid.
func (d *ServerDescriptor) Validate() error {
	for _, keyword := range requiredKeywords {
		_, ok := d.keywords[keyword]
		if !ok {
			return ServerDescriptorMissingFieldError(keyword)
		}
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
