package pearl

import "fmt"

// Command represents a cell packet command byte.
type Command byte

// Enumerate all possible cell commands.
//
// Reference: https://github.com/torproject/torspec/blob/master/tor-spec.txt#L418-L438
//
//	   The 'Command' field of a fixed-length cell holds one of the following
//	   values:
//	         0 -- PADDING     (Padding)                 (See Sec 7.2)
//	         1 -- CREATE      (Create a circuit)        (See Sec 5.1)
//	         2 -- CREATED     (Acknowledge create)      (See Sec 5.1)
//	         3 -- RELAY       (End-to-end data)         (See Sec 5.5 and 6)
//	         4 -- DESTROY     (Stop using a circuit)    (See Sec 5.4)
//	         5 -- CREATE_FAST (Create a circuit, no PK) (See Sec 5.1)
//	         6 -- CREATED_FAST (Circuit created, no PK) (See Sec 5.1)
//	         8 -- NETINFO     (Time and address info)   (See Sec 4.5)
//	         9 -- RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
//	         10 -- CREATE2    (Extended CREATE cell)    (See Sec 5.1)
//	         11 -- CREATED2   (Extended CREATED cell)    (See Sec 5.1)
//	
//	    Variable-length command values are:
//	         7 -- VERSIONS    (Negotiate proto version) (See Sec 4)
//	         128 -- VPADDING  (Variable-length padding) (See Sec 7.2)
//	         129 -- CERTS     (Certificates)            (See Sec 4.2)
//	         130 -- AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
//	         131 -- AUTHENTICATE (Client authentication)(See Sec 4.5)
//	         132 -- AUTHORIZE (Client authorization)    (Not yet used)
//
const (
	Padding       Command = 0
	Create        Command = 1
	Created       Command = 2
	Relay         Command = 3
	Destroy       Command = 4
	CreateFast    Command = 5
	CreatedFast   Command = 6
	Netinfo       Command = 8
	RelayEarly    Command = 9
	Create2       Command = 10
	Created2      Command = 11
	Versions      Command = 7
	Vpadding      Command = 128
	Certs         Command = 129
	AuthChallenge Command = 130
	Authenticate  Command = 131
	Authorize     Command = 132
)

var commandStrings = map[Command]string{
	0:   "PADDING",
	1:   "CREATE",
	2:   "CREATED",
	3:   "RELAY",
	4:   "DESTROY",
	5:   "CREATE_FAST",
	6:   "CREATED_FAST",
	8:   "NETINFO",
	9:   "RELAY_EARLY",
	10:  "CREATE2",
	11:  "CREATED2",
	7:   "VERSIONS",
	128: "VPADDING",
	129: "CERTS",
	130: "AUTH_CHALLENGE",
	131: "AUTHENTICATE",
	132: "AUTHORIZE",
}

func (c Command) String() string {
	s, ok := commandStrings[c]
	if ok {
		return s
	}
	return fmt.Sprintf("Command(%d)", byte(c))
}

// IsCommand determines whether the given byte is a recognized cell command.
func IsCommand(c byte) bool {
	_, ok := commandStrings[c]
	return ok
}
