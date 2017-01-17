package tordir

import (
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/mmcloughlin/pearl/torkeys"
)

const (
	routerKeyword    = "router"
	bandwidthKeyword = "bandwidth"
	publishedKeyword = "published"
	onionKeyKeyword  = "onion-key"
)

var requiredKeywords = []string{
	routerKeyword,
	bandwidthKeyword,
	publishedKeyword,
	onionKeyKeyword,
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

// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L1180-L1181
//
//	   nickname ::= between 1 and 19 alphanumeric characters ([A-Za-z0-9]),
//	      case-insensitive.
//
var nicknameRx = regexp.MustCompile(`^[[:alnum:]]{1,19}$`)

// SetRouter sets the router description. This is required.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L379-L394
//
//	     "router" nickname address ORPort SOCKSPort DirPort NL
//
//	       [At start, exactly once.]
//
//	       Indicates the beginning of a server descriptor.  "nickname" must be a
//	       valid router nickname as specified in section 2.1.3.  "address" must
//	       be an IPv4
//	       address in dotted-quad format.  The last three numbers indicate the
//	       TCP ports at which this OR exposes functionality. ORPort is a port at
//	       which this OR accepts TLS connections for the main OR protocol;
//	       SOCKSPort is deprecated and should always be 0; and DirPort is the
//	       port at which this OR accepts directory-related HTTP connections.  If
//	       any port is not supported, the value 0 is given instead of a port
//	       number.  (At least one of DirPort and ORPort SHOULD be set;
//	       authorities MAY reject any descriptor with both DirPort and ORPort of
//	       0.)
//
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
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L419-L430
//
//	    "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed NL
//
//	       [Exactly once]
//
//	       Estimated bandwidth for this router, in bytes per second.  The
//	       "average" bandwidth is the volume per second that the OR is willing to
//	       sustain over long periods; the "burst" bandwidth is the volume that
//	       the OR is willing to sustain in very short intervals.  The "observed"
//	       value is an estimate of the capacity this relay can handle.  The
//	       relay remembers the max bandwidth sustained output over any ten
//	       second period in the past day, and another sustained input.  The
//	       "observed" value is the lesser of these two numbers.
//
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
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L440-L445
//
//	    "published" YYYY-MM-DD HH:MM:SS NL
//
//	       [Exactly once]
//
//	       The time, in UTC, when this descriptor (and its corresponding
//	       extra-info document if any)  was generated.
//
func (d *ServerDescriptor) SetPublishedTime(t time.Time) error {
	args := []string{
		t.In(time.UTC).Format("2006-01-02 15:04:05"),
	}
	d.addItem(NewItem(publishedKeyword, args))
	return nil
}

// SetOnionKey sets the "onion key" used to encrypt CREATE cells for this
// router.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L475-L486
//
//	    "onion-key" NL a public key in PEM format
//
//	       [Exactly once]
//	       [No extra arguments]
//
//	       This key is used to encrypt CREATE cells for this OR.  The key MUST be
//	       accepted for at least 1 week after any new key is published in a
//	       subsequent descriptor. It MUST be 1024 bits.
//
//	       The key encoding is the encoding of the key as a PKCS#1 RSAPublicKey
//	       structure, encoded in base64, and wrapped in "-----BEGIN RSA PUBLIC
//	       KEY-----" and "-----END RSA PUBLIC KEY-----".
//
func (d *ServerDescriptor) SetOnionKey(k torkeys.PublicKey) error {
	der, err := k.MarshalPKCS1PublicKeyDER()
	if err != nil {
		return err
	}

	obj := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	item := NewItemWithObject(onionKeyKeyword, []string{}, obj)
	d.addItem(item)

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
