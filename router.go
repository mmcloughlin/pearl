package pearl

import (
	"crypto/rsa"
	"net"
	"time"

	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/meta"
	"github.com/mmcloughlin/pearl/torconfig"
	"github.com/mmcloughlin/pearl/torcrypto"
	"github.com/mmcloughlin/pearl/tordir"
	"github.com/mmcloughlin/pearl/torexitpolicy"
	"github.com/pkg/errors"
	"github.com/uber-go/tally"
)

// Router is a Tor router.
type Router struct {
	config      *torconfig.Config
	fingerprint []byte

	connections *ConnectionManager

	metrics *Metrics
	scope   tally.Scope
	logger  log.Logger
}

// TODO(mbm): determine which parts of Router struct are required for client and
// server. Perhaps a stripped down struct can be used for client-only.

// NewRouter constructs a router based on the given config.
func NewRouter(config *torconfig.Config, scope tally.Scope, logger log.Logger) (*Router, error) {
	fingerprint, err := torcrypto.Fingerprint(&config.Keys.Identity.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute fingerprint")
	}

	logger = log.ForComponent(logger, "router")
	return &Router{
		config:      config,
		fingerprint: fingerprint,
		connections: NewConnectionManager(),
		metrics:     NewMetrics(scope, logger),
		scope:       scope,
		logger:      logger,
	}, nil
}

// IdentityKey returns the identity key of the router.
func (r *Router) IdentityKey() *rsa.PrivateKey {
	return r.config.Keys.Identity
}

// Fingerprint returns the router fingerprint.
func (r *Router) Fingerprint() []byte {
	return r.fingerprint
}

// Serve starts a listener and enters a main loop handling connections.
func (r *Router) Serve() error {
	laddr := r.config.ORAddr()
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

		go func() {
			if err := c.Serve(); err != nil {
				log.Err(r.logger, err, "error serving connection")
			}
		}()
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
	err = c.StartClient()
	if err != nil {
		return nil, errors.Wrap(err, "error starting client")
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
func (r *Router) Descriptor() (*tordir.ServerDescriptor, error) {
	s := tordir.NewServerDescriptor()

	if err := s.SetRouter(r.config.Nickname, r.config.IP, r.config.ORPort, 0); err != nil {
		return nil, err
	}
	if err := s.SetSigningKey(r.IdentityKey()); err != nil {
		return nil, err
	}
	if err := s.SetOnionKey(&r.config.Keys.Onion.PublicKey); err != nil {
		return nil, err
	}

	s.SetNtorOnionKey(r.config.Keys.Ntor)
	s.SetPlatform(r.config.Platform)
	s.SetContact(r.config.Contact)
	// TODO(mbm): publish real bandwidth values
	s.SetBandwidth(r.config.BandwidthAverage, r.config.BandwidthBurst, r.config.BandwidthAverage)
	s.SetPublishedTime(time.Now())
	s.SetExitPolicy(torexitpolicy.RejectAllPolicy)
	s.SetProtocols(meta.Protocols)

	return s, nil
}
