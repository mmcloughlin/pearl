package tordir

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/mmcloughlin/pearl/protover"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/mmcloughlin/pearl/torexitpolicy"
)

const (
	routerKeyword          = "router"
	bandwidthKeyword       = "bandwidth"
	publishedKeyword       = "published"
	onionKeyKeyword        = "onion-key"
	signingKeyKeyword      = "signing-key"
	fingerprintKeyword     = "fingerprint"
	routerSignatureKeyword = "router-signature"
	acceptKeyword          = "accept"
	rejectKeyword          = "reject"
	ntorOnionKeyKeyword    = "ntor-onion-key"
	platformKeyword        = "platform"
	protoKeyword           = "proto"
	contactKeyword         = "contact"
)

var requiredKeywords = []string{
	routerKeyword,
	bandwidthKeyword,
	publishedKeyword,
	onionKeyKeyword,
	signingKeyKeyword,
	fingerprintKeyword,
}

// Potential errors when constructing a server descriptor.
var (
	ErrServerDescriptorBadNickname  = errors.New("invalid nickname")
	ErrServerDescriptorNotIPv4      = errors.New("require ipv4 address")
	ErrServerDescriptorNoExitPolicy = errors.New("missing exit policy")
)

// ErrServerDescriptorPublishBadStatus is returned from a publish operation
// when a non-200 HTTP response is received.
var ErrServerDescriptorPublishBadStatus = errors.New("received non-200 on publish")

// ServerDescriptorMissingFieldError indicates that a required field is
// missing from a server descriptor.
type ServerDescriptorMissingFieldError string

func (e ServerDescriptorMissingFieldError) Error() string {
	return fmt.Sprintf("missing field '%s'", string(e))
}

// ServerDescriptor is a builder for a server descriptor to be published to
// directory servers.
type ServerDescriptor struct {
	router     *Item
	items      []*Item
	keywords   map[string]bool
	signingKey *rsa.PrivateKey
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

// SetPlatform sets the platform (software, version, OS) of the server
// descriptor.
func (d *ServerDescriptor) SetPlatform(platform string) error {
	d.addItem(NewItem(platformKeyword, []string{platform}))
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

// SetExitPolicy adds a specification of the given exit policy to the
// descriptor.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L554-L564
//
//	    "accept" exitpattern NL
//	    "reject" exitpattern NL
//
//	       [Any number]
//
//	       These lines describe an "exit policy": the rules that an OR follows
//	       when deciding whether to allow a new stream to a given address.  The
//	       'exitpattern' syntax is described below.  There MUST be at least one
//	       such entry.  The rules are considered in order; if no rule matches,
//	       the address will be accepted.  For clarity, the last such entry SHOULD
//	       be accept *:* or reject *:*.
//
func (d *ServerDescriptor) SetExitPolicy(policy *torexitpolicy.Policy) error {
	for _, rule := range policy.Rules() {
		keyword := rule.Action.Describe()
		args := []string{rule.Pattern.Describe()}
		d.addItem(NewItem(keyword, args))
	}
	return nil
}

// SetProtocols specifies which sub-protocols the router supports.
func (d *ServerDescriptor) SetProtocols(p protover.SupportedProtocols) error {
	d.addItem(NewItem(protoKeyword, p.Strings()))
	return nil
}

// SetContact sets contact information for the server administrator.
func (d *ServerDescriptor) SetContact(c string) {
	// Reference: https://github.com/torproject/torspec/blob/4074b891e53e8df951fc596ac6758d74da290c60/dir-spec.txt#L2012-L2018
	//
	//	    "contact" SP string NL
	//	
	//	        [Exactly once]
	//	
	//	        An arbitrary string describing how to contact the directory
	//	        server's administrator.  Administrators should include at least an
	//	        email address and a PGP fingerprint.
	//
	d.addItem(NewItem(contactKeyword, []string{c}))
}

// SetNtorOnionKey sets the key used for ntor circuit extended handshake.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L513-L522
//
//	    "ntor-onion-key" base-64-encoded-key
//
//	       [At most once]
//
//	       A curve25519 public key used for the ntor circuit extended
//	       handshake.  It's the standard encoding of the OR's curve25519
//	       public key, encoded in base 64.  The trailing '=' sign MAY be
//	       omitted from the base64 encoding.  The key MUST be accepted
//	       for at least 1 week after any new key is published in a
//	       subsequent descriptor.
//
func (d *ServerDescriptor) SetNtorOnionKey(k *torcrypto.Curve25519KeyPair) error {
	args := []string{
		base64.RawStdEncoding.EncodeToString(k.Public[:]),
	}
	d.addItem(NewItem(ntorOnionKeyKeyword, args))
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
func (d *ServerDescriptor) SetOnionKey(k *rsa.PublicKey) error {
	item, err := newItemWithKey(onionKeyKeyword, k)
	if err != nil {
		return err
	}

	d.addItem(item)
	return nil
}

// SetSigningKey sets the router's identity key, used to sign the descriptor
// document.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L545-L552
//
//	    "signing-key" NL a public key in PEM format
//
//	       [Exactly once]
//	       [No extra arguments]
//
//	       The OR's long-term RSA identity key.  It MUST be 1024 bits.
//
//	       The encoding is as for "onion-key" above.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L447-L457
//
//	    "fingerprint" fingerprint NL
//
//	       [At most once]
//
//	       A fingerprint (a HASH_LEN-byte of asn1 encoded public key, encoded in
//	       hex, with a single space after every 4 characters) for this router's
//	       identity key. A descriptor is considered invalid (and MUST be
//	       rejected) if the fingerprint line does not match the public key.
//
//	       [We didn't start parsing this line until Tor 0.1.0.6-rc; it should
//	        be marked with "opt" until earlier versions of Tor are obsolete.]
//
func (d *ServerDescriptor) SetSigningKey(k *rsa.PrivateKey) error {
	item, err := newItemWithKey(signingKeyKeyword, &k.PublicKey)
	if err != nil {
		return err
	}

	d.addItem(item)

	err = d.setFingerprint(&k.PublicKey)
	if err != nil {
		return err
	}

	d.signingKey = k

	return nil
}

func (d *ServerDescriptor) setFingerprint(k *rsa.PublicKey) error {
	h, err := torcrypto.Fingerprint(k)
	if err != nil {
		return err
	}

	args := []string{}
	for i := 0; i < len(h); i += 2 {
		chunk := fmt.Sprintf("%04X", h[i:i+2])
		args = append(args, chunk)
	}

	item := NewItem(fingerprintKeyword, args)
	d.addItem(item)
	return nil
}

// Validate checks whether the descriptor is valid.
func (d *ServerDescriptor) Validate() error {
	for _, keyword := range requiredKeywords {
		if !d.hasKeyword(keyword) {
			return ServerDescriptorMissingFieldError(keyword)
		}
	}

	// confirm it has an exit policy (accept and/or reject keywords)
	if !d.hasKeyword(acceptKeyword) && !d.hasKeyword(rejectKeyword) {
		return ErrServerDescriptorNoExitPolicy
	}

	return nil
}

func (d *ServerDescriptor) hasKeyword(keyword string) bool {
	_, ok := d.keywords[keyword]
	return ok
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

	err = d.sign(doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// sign appends a signature to the document using this descriptors signing
// key.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L593-L602
//
//	    "router-signature" NL Signature NL
//
//	       [At end, exactly once]
//	       [No extra arguments]
//
//	       The "SIGNATURE" object contains a signature of the PKCS1-padded
//	       hash of the entire server descriptor, taken from the beginning of the
//	       "router" line, through the newline after the "router-signature" line.
//	       The server descriptor is invalid unless the signature is performed
//	       with the router's identity key.
//
func (d *ServerDescriptor) sign(doc *Document) error {
	item := NewItemKeywordOnly(routerSignatureKeyword)
	doc.AddItem(item)

	data := doc.Encode()
	sig, err := torcrypto.SignRSASHA1(data, d.signingKey)
	if err != nil {
		return err
	}

	item.Object = &pem.Block{
		Type:  "SIGNATURE",
		Bytes: sig,
	}

	return nil
}

// PublishToAuthority publishes this server descriptor to the authority with
// the given address (in host:port format).
func (d *ServerDescriptor) PublishToAuthority(addr string) error {
	doc, err := d.Document()
	if err != nil {
		return err
	}

	u := &url.URL{
		Scheme: "http",
		Host:   addr,
		Path:   "/tor/",
	}

	body := bytes.NewReader(doc.Encode())

	resp, err := http.Post(u.String(), "tor/descriptor", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L3434-L3458
	//
	//	6.2. HTTP status codes
	//
	//	  Tor delivers the following status codes.  Some were chosen without much
	//	  thought; other code SHOULD NOT rely on specific status codes yet.
	//
	//	  200 -- the operation completed successfully
	//	      -- the user requested statuses or serverdescs, and none of the ones we
	//	         requested were found (0.2.0.4-alpha and earlier).
	//
	//	  304 -- the client specified an if-modified-since time, and none of the
	//	         requested resources have changed since that time.
	//
	//	  400 -- the request is malformed, or
	//	      -- the URL is for a malformed variation of one of the URLs we support,
	//	          or
	//	      -- the client tried to post to a non-authority, or
	//	      -- the authority rejected a malformed posted document, or
	//
	//	  404 -- the requested document was not found.
	//	      -- the user requested statuses or serverdescs, and none of the ones
	//	         requested were found (0.2.0.5-alpha and later).
	//
	//	  503 -- we are declining the request in order to save bandwidth
	//	      -- user requested some items that we ordinarily generate or store,
	//	         but we do not have any available.
	//

	if resp.StatusCode != http.StatusOK {
		return ErrServerDescriptorPublishBadStatus
	}

	return nil
}

// PublishPublic publishes the server descriptor to the known public Tor
// directory authorities.
func (d *ServerDescriptor) PublishPublic() error {
	for _, addr := range Authorities {
		err := d.PublishToAuthority(addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func newItemWithKey(keyword string, k *rsa.PublicKey) (*Item, error) {
	der, err := torcrypto.MarshalRSAPublicKeyPKCS1DER(k)
	if err != nil {
		return nil, err
	}

	obj := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	return NewItemWithObject(keyword, []string{}, obj), nil
}
