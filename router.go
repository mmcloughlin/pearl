package pearl

import (
	"fmt"
	"net"
	"time"

	"github.com/mmcloughlin/openssl"
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/mmcloughlin/pearl/tordir"
	"github.com/mmcloughlin/pearl/torexitpolicy"
	"github.com/mmcloughlin/pearl/torkeys"
	"github.com/pkg/errors"
)

// Router is a Tor router.
type Router struct {
	config *torconfig.Config

	idKey    openssl.PrivateKey
	onionKey openssl.PrivateKey
	ntorKey  *torkeys.Curve25519KeyPair

	logger log.Logger
}

// NewRouter constructs a router based on the given config.
func NewRouter(config *torconfig.Config, logger log.Logger) (*Router, error) {
	idKey, err := torkeys.GenerateRSA()
	if err != nil {
		return nil, err
	}

	onionKey, err := torkeys.GenerateRSA()
	if err != nil {
		return nil, err
	}

	ntorKey, err := torkeys.GenerateCurve25519KeyPair()
	if err != nil {
		return nil, err
	}

	return &Router{
		config:   config,
		idKey:    idKey,
		onionKey: onionKey,
		ntorKey:  ntorKey,
		logger:   log.ForComponent(logger, "router"),
	}, nil
}

// IdentityKey returns the identity key of the router.
func (r *Router) IdentityKey() openssl.PrivateKey {
	return r.idKey
}

// Run starts a listener and enters a main loop handling connections.
func (r *Router) Run() error {
	laddr := fmt.Sprintf(":%d", r.config.ORPort)
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

		c, err := NewConnection(r, conn, r.logger)
		if err != nil {
			return errors.Wrap(err, "error building connection")
		}

		go c.Handle()
	}
}

// Descriptor returns a server descriptor for this router.
func (r *Router) Descriptor() *tordir.ServerDescriptor {
	s := tordir.NewServerDescriptor()
	s.SetRouter(r.config.Nickname, net.IPv4(127, 0, 0, 1), r.config.ORPort, 0)
	s.SetPlatform(r.config.Platform)
	s.SetBandwidth(1000, 2000, 500)
	s.SetPublishedTime(time.Now())
	s.SetExitPolicy(torexitpolicy.RejectAllPolicy)
	s.SetSigningKey(r.IdentityKey())
	s.SetOnionKey(r.onionKey)
	s.SetNtorOnionKey(r.ntorKey)
	return s
}
