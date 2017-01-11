package tordir

import (
	"bytes"
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

type Document struct {
	Items []Item
}

func (d Document) Encode() []byte {
	buf := bytes.NewBuffer(nil)
	for _, item := range d.Items {
		buf.Write(item.Encode())
	}
	return buf.Bytes()
}

type Item struct {
	Keyword    string
	Whitespace string
	Arguments  []string
	Object     *pem.Block
}

func (it Item) Encode() []byte {
	s := it.Keyword + it.Whitespace + strings.Join(it.Arguments, " ") + "\n"
	if it.Object != nil {
		s += string(pem.EncodeToMemory(it.Object))
	}
	return []byte(s)
}

// XXX cite ref
// NL = The ascii LF character (hex value 0x0a).
// Document ::= (Item | NL)+
// Item ::= KeywordLine Object*
// KeywordLine ::= Keyword NL | Keyword WS ArgumentChar+ NL
// Keyword = KeywordChar+
// KeywordChar ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9' | '-'
// ArgumentChar ::= any printing ASCII character except NL.
// WS = (SP | TAB)+
// Object ::= BeginLine Base64-encoded-data EndLine
// BeginLine ::= "-----BEGIN " Keyword "-----" NL
// EndLine ::= "-----END " Keyword "-----" NL

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
		item := Item{
			Keyword:    string(match[1]),
			Whitespace: string(match[3]),
			Arguments:  args,
			Object:     block,
		}

		doc.Items = append(doc.Items, item)

		n += len(match[0])
	}

	if n != len(b) {
		return nil, ErrParseUnrecognizedData
	}

	return doc, nil
}
