package pearl

import (
	"time"

	"github.com/mmcloughlin/pearl/log"
)

// Insert: https://github.com/torproject/torspec/blob/f66d1826c0b32d307898bba081dbf8ef598d4037/dir-spec.txt#L341-L371

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
