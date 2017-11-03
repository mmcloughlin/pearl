package pearl

import (
	"time"

	"github.com/mmcloughlin/pearl/log"
)

// Reference: https://github.com/torproject/torspec/blob/f66d1826c0b32d307898bba081dbf8ef598d4037/dir-spec.txt#L341-L371
//
//	2.1. Uploading server descriptors and extra-info documents
//
//	   ORs SHOULD generate a new server descriptor and a new extra-info
//	   document whenever any of the following events have occurred:
//
//	      - A period of time (18 hrs by default) has passed since the last
//	        time a descriptor was generated.
//
//	      - A descriptor field other than bandwidth or uptime has changed.
//
//	      - Bandwidth has changed by a factor of 2 from the last time a
//	        descriptor was generated, and at least a given interval of time
//	        (20 mins by default) has passed since then.
//
//	      - Its uptime has been reset (by restarting).
//
//	      [XXX this list is incomplete; see router_differences_are_cosmetic()
//	       in routerlist.c for others]
//
//	   ORs SHOULD NOT publish a new server descriptor or extra-info document
//	   if none of the above events have occurred and not much time has passed
//	   (12 hours by default).
//
//	   After generating a descriptor, ORs upload them to every directory
//	   authority they know, by posting them (in order) to the URL
//
//	      http://<hostname:port>/tor/
//
//	   Server descriptors may not exceed 20,000 bytes in length; extra-info
//	   documents may not exceed 50,000 bytes in length. If they do, the
//	   authorities SHOULD reject them.
//

type Publisher struct {
	Router      *Router
	Interval    time.Duration
	Authorities []string

	Logger log.Logger
}

func (p *Publisher) Publish() error {
	desc, err := p.Router.Descriptor()
	if err != nil {
		return err
	}

	data := p.Router.config.Data
	err = data.SetServerDescriptor(desc)
	if err != nil {
		return err
	}

	for _, addr := range p.Authorities {
		err = desc.PublishToAuthority(addr)
		lg := p.Logger.With("authority", addr)
		if err != nil {
			log.Err(lg, err, "failed to publish descriptor")
		} else {
			lg.Info("published descriptor")
		}
	}

	return nil
}

func (p *Publisher) Start() {
	for {
		err := p.Publish()
		if err != nil {
			log.Err(p.Logger, err, "error publishing descriptor")
			return
		}
		time.Sleep(p.Interval)
	}
}
