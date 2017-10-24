package pearl

import (
	"github.com/mmcloughlin/pearl/log"
	"github.com/mmcloughlin/pearl/telemetry"
	"github.com/uber-go/tally"
)

type Metrics struct {
	Connections telemetry.ResourceMetric
	Circuits    telemetry.ResourceMetric
	Inbound     *telemetry.Bandwidth
	Outbound    *telemetry.Bandwidth
}

func NewMetrics(scope tally.Scope, l log.Logger) *Metrics {
	return &Metrics{
		Connections: telemetry.NewResourceMetric(scope, l, "connections"),
		Circuits:    telemetry.NewResourceMetric(scope, l, "circuits"),
		Inbound:     telemetry.NewBandwidth(scope.Counter("inbound_bytes")),
		Outbound:    telemetry.NewBandwidth(scope.Counter("outbound_bytes")),
	}
}
