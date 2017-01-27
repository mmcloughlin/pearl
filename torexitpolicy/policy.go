package torexitpolicy

import "net"

// Action specifies how a set of addresses should be handled.
type Action bool

// Accept and Reject are the two possible actions to take.
const (
	Accept Action = true
	Reject Action = false
)

// Describe represents the action as a string, "accept" or "reject".
func (a Action) Describe() string {
	if bool(a) {
		return "accept"
	}
	return "reject"
}

// Pattern specifies a set of addresses to apply an action to.
//
// Reference: https://github.com/torproject/torspec/blob/master/dir-spec.txt#L1186-L1201
//
//	   exitpattern ::= addrspec ":" portspec
//	   portspec ::= "*" | port | port "-" port
//	   port ::= an integer between 1 and 65535, inclusive.
//	
//	      [Some implementations incorrectly generate ports with value 0.
//	       Implementations SHOULD accept this, and SHOULD NOT generate it.
//	       Connections to port 0 are never permitted.]
//	
//	   addrspec ::= "*" | ip4spec | ip6spec
//	   ipv4spec ::= ip4 | ip4 "/" num_ip4_bits | ip4 "/" ip4mask
//	   ip4 ::= an IPv4 address in dotted-quad format
//	   ip4mask ::= an IPv4 mask in dotted-quad format
//	   num_ip4_bits ::= an integer between 0 and 32
//	   ip6spec ::= ip6 | ip6 "/" num_ip6_bits
//	   ip6 ::= an IPv6 address, surrounded by square brackets.
//	   num_ip6_bits ::= an integer between 0 and 128
//
type Pattern interface {
	Matches(net.IP, uint16) bool
	Describe() string
}

//go:generate mockery -name=Pattern -case=underscore

// AllPattern represents the pattern "*:*" that matches anything.
var AllPattern Pattern = allPattern{}

type allPattern struct{}

func (a allPattern) Matches(_ net.IP, _ uint16) bool {
	return true
}

func (a allPattern) Describe() string {
	return "*:*"
}

// Rule specifies an Action to apply to addresses matched by Pattern.
type Rule struct {
	Action  Action
	Pattern Pattern
}

// Policy defines which addresses to allow traffic to.
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
type Policy struct {
	rules         []Rule
	defaultAction Action
}

// RejectAllPolicy does not allow any exit traffic.
var RejectAllPolicy = NewPolicyWithDefault(Reject)

// AcceptAllPolicy does not allow any exit traffic.
var AcceptAllPolicy = NewPolicyWithDefault(Accept)

// NewPolicy builds an empty policy. By default this will reject all
// addresses.
func NewPolicy() *Policy {
	return NewPolicyWithDefault(Reject)
}

// NewPolicyWithDefault builds a Policy with the specified default behavior.
func NewPolicyWithDefault(a Action) *Policy {
	return &Policy{defaultAction: a}
}

// AddRule adds a rule to the policy. Rules are processed in the order they
// are added.
func (p *Policy) AddRule(r Rule) {
	p.rules = append(p.rules, r)
}

// Action adds a rule that applies the Action a to addresses matched by
// Pattern pat.
func (p *Policy) Action(a Action, pat Pattern) {
	p.AddRule(Rule{
		Action:  a,
		Pattern: pat,
	})
}

// Accept adds a rule to accept addresses matched by the Pattern.
func (p *Policy) Accept(pat Pattern) {
	p.Action(Accept, pat)
}

// Reject adds a rule to reject addresses matched by the Pattern.
func (p *Policy) Reject(pat Pattern) {
	p.Action(Reject, pat)
}

// Rules returns all the rules in the policy. The default rule is included at
// the end.
func (p Policy) Rules() []Rule {
	return append(p.rules, Rule{Action: p.defaultAction, Pattern: AllPattern})
}

// Allow determines whether the pollicy allows exist traffic to the given
// addr:port.
func (p Policy) Allow(ip net.IP, port uint16) bool {
	for _, r := range p.rules {
		if r.Pattern.Matches(ip, port) {
			return bool(r.Action)
		}
	}
	return bool(p.defaultAction)
}
