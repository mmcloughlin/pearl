package tordir

import (
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// Parsing errors.
var (
	ErrParseBadPEMBlock      = errors.New("bad pem block")
	ErrParseUnrecognizedData = errors.New("document contained unrecognized data")
)

// Document represents a Tor directory document.
type Document struct {
	items []*Item
}

// AddItem adds the item to the Document.
func (d *Document) AddItem(item *Item) {
	d.items = append(d.items, item)
}

// Encode converts the document to bytes.
func (d Document) Encode() []byte {
	doc := []byte{}
	for _, item := range d.items {
		doc = append(doc, item.Encode()...)
	}
	return doc
}

// Item is an entry in a Tor directory document.
type Item struct {
	Keyword    string
	Whitespace string
	Arguments  []string
	Object     *pem.Block
}

// NewItemWithObject constructs an item with the given arguments with an
// associated object.
func NewItemWithObject(keyword string, args []string, obj *pem.Block) *Item {
	return &Item{
		Keyword:    keyword,
		Whitespace: " ",
		Arguments:  args,
		Object:     obj,
	}
}

// NewItem constructs an item without an object.
func NewItem(keyword string, args []string) *Item {
	return NewItemWithObject(keyword, args, nil)
}

// NewItemKeywordOnly constructs an item that only has a keyword.
func NewItemKeywordOnly(keyword string) *Item {
	return NewItem(keyword, []string{})
}

// Encode converts the item to bytes.
func (it Item) Encode() []byte {
	s := it.Keyword
	if len(it.Arguments) > 0 {
		s += it.Whitespace + strings.Join(it.Arguments, " ")
	}
	s += "\n"
	if it.Object != nil {
		s += string(pem.EncodeToMemory(it.Object))
	}
	return []byte(s)
}

// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L194-L221
//
//	1.2. Document meta-format
//
//	  Server descriptors, directories, and running-routers documents all obey the
//	  following lightweight extensible information format.
//
//	  The highest level object is a Document, which consists of one or more
//	  Items.  Every Item begins with a KeywordLine, followed by zero or more
//	  Objects. A KeywordLine begins with a Keyword, optionally followed by
//	  whitespace and more non-newline characters, and ends with a newline.  A
//	  Keyword is a sequence of one or more characters in the set [A-Za-z0-9-].
//	  An Object is a block of encoded data in pseudo-Open-PGP-style
//	  armor. (cf. RFC 2440)
//
//	  More formally:
//
//	    NL = The ascii LF character (hex value 0x0a).
//	    Document ::= (Item | NL)+
//	    Item ::= KeywordLine Object*
//	    KeywordLine ::= Keyword NL | Keyword WS ArgumentChar+ NL
//	    Keyword = KeywordChar+
//	    KeywordChar ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9' | '-'
//	    ArgumentChar ::= any printing ASCII character except NL.
//	    WS = (SP | TAB)+
//	    Object ::= BeginLine Base64-encoded-data EndLine
//	    BeginLine ::= "-----BEGIN " Keyword "-----" NL
//	    EndLine ::= "-----END " Keyword "-----" NL
//
//	    The BeginLine and EndLine of an Object must use the same keyword.
//
const (
	nlExpr          = `\n*`
	keywordExpr     = `[[:alnum:]\-]+`
	argumentExpr    = `[[:print:]]+`
	wsExpr          = `[[:blank:]]+`
	keywordLineExpr = nlExpr + "(" + keywordExpr + `)((` + wsExpr + `)(` + argumentExpr + `))?\n`

	beginExpr  = "-----BEGIN (.+)-----\n"
	endExpr    = "-----END (.+)-----\n"
	base64Expr = "([a-zA-Z0-9/+=\n]+)"
	objectExpr = beginExpr + base64Expr + endExpr

	itemExpr = nlExpr + keywordLineExpr + "(" + objectExpr + ")?" + nlExpr
)

var itemRx *regexp.Regexp

func init() {
	itemRx = regexp.MustCompile(itemExpr)
	itemRx.Longest()
}

// Parse parses a Tor directory document.
func Parse(b []byte) (*Document, error) {
	matches := itemRx.FindAllSubmatch(b, -1)

	doc := &Document{}

	n := 0
	for _, match := range matches {
		block, _ := pem.Decode(match[5])
		if len(match[5]) > 0 && block == nil {
			return nil, ErrParseBadPEMBlock
		}

		args := strings.Split(string(match[4]), " ")
		item := &Item{
			Keyword:    string(match[1]),
			Whitespace: string(match[3]),
			Arguments:  args,
			Object:     block,
		}

		doc.AddItem(item)

		n += len(match[0])
	}

	if n != len(b) {
		return nil, ErrParseUnrecognizedData
	}

	return doc, nil
}
