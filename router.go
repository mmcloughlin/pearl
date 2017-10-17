package pearl

import (
	"crypto/rsa"
	"fmt"
	"net"
	"time"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/meta"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/mmcloughlin/pearl/tordir"
	"github.com/mmcloughlin/pearl/torexitpolicy"
	"github.com/pkg/errors"
)

// Router is a Tor router.
type Router struct {
	config *torconfig.Config

	idKey       *rsa.PrivateKey
	onionKey    *rsa.PrivateKey
	ntorKey     *torcrypto.Curve25519KeyPair
	fingerprint []byte

	connections *ConnectionManager

	logger log.Logger
}

// TODO(mbm): determine which parts of Router struct are required for client and
// server. Perhaps a stripped down struct can be used for client-only.

// NewRouter constructs a router based on the given config.
func NewRouter(config *torconfig.Config, logger log.Logger) (*Router, error) {
	idKey, err := torcrypto.GenerateRSA()
	if err != nil {
		return nil, err
	}

	onionKey, err := torcrypto.GenerateRSA()
	if err != nil {
		return nil, err
	}

	ntorKey, err := torcrypto.GenerateCurve25519KeyPair()
	if err != nil {
		return nil, err
	}

	fingerprint, err := torcrypto.Fingerprint(&idKey.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute fingerprint")
	}

	logger = log.ForComponent(logger, "router")
	logger = log.WithBytes(logger, "fingerprint", fingerprint)
	return &Router{
		config:      config,
		idKey:       idKey,
		onionKey:    onionKey,
		ntorKey:     ntorKey,
		fingerprint: fingerprint,
		connections: NewConnectionManager(),
		logger:      logger,
	}, nil
}

// IdentityKey returns the identity key of the router.
func (r *Router) IdentityKey() *rsa.PrivateKey {
	return r.idKey
}

// Fingerprint returns the router fingerprint.
func (r *Router) Fingerprint() []byte {
	return r.fingerprint
}

// Serve starts a listener and enters a main loop handling connections.
func (r *Router) Serve() error {
	laddr := fmt.Sprintf("localhost:%d", r.config.ORPort)
	r.logger.With("laddr", laddr).Info("creating listener")
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return errors.Wrap(err, "could not create listener")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return errors.Wrap(err, "error accepting connection")
		}

		c, err := NewServer(r, conn, r.logger)
		if err != nil {
			return errors.Wrap(err, "error building connection")
		}

		go c.Handle()
	}
}

func (r *Router) Connect(raddr string) (*Connection, error) {
	conn, err := net.Dial("tcp", raddr)
	if err != nil {
		return nil, errors.Wrap(err, "dial failed")
	}

	c, err := NewClient(r, conn, r.logger)
	if err != nil {
		return nil, errors.Wrap(err, "building connection failed")
	}

	// TODO(mbm): should we be calling this here?
	err = c.clientHandshake()
	if err != nil {
		return nil, errors.Wrap(err, "handshake failed")
	}

	return c, nil
}

// Connection returns a connection to the indicated relay. Returns an existing
// connection, if it exists. Otherwise opens a connection and returns it.
func (r *Router) Connection(hint ConnectionHint) (*Connection, error) {
	fp, err := hint.Fingerprint()
	if err != nil {
		return nil, errors.Wrap(err, "missing fingerprint from connection hint")
	}

	if conn, ok := r.connections.Connection(fp); ok {
		return conn, nil
	}

	addrs, err := hint.Addresses()
	if err != nil {
		return nil, errors.Wrap(err, "no addresses provided")
	}

	for _, addr := range addrs {
		raddr := addr.String()
		conn, err := r.Connect(raddr)
		if err != nil {
			log.WithErr(r.logger, err).Warn("connection attempt failed")
			continue
		}
		return conn, nil
	}

	return nil, errors.New("all connection attempts failed")
}

// Descriptor returns a server descriptor for this router.
func (r *Router) Descriptor() *tordir.ServerDescriptor {
	s := tordir.NewServerDescriptor()
	s.SetRouter(r.config.Nickname, net.IPv4(127, 0, 0, 1), r.config.ORPort, 0)
	s.SetPlatform(r.config.Platform)
	s.SetBandwidth(1000, 2000, 500)
	s.SetPublishedTime(time.Now())
	s.SetExitPolicy(torexitpolicy.RejectAllPolicy)
	s.SetProtocols(meta.Protocols)
	s.SetSigningKey(r.IdentityKey())
	s.SetOnionKey(&r.onionKey.PublicKey)
	s.SetNtorOnionKey(r.ntorKey)
	return s
}
