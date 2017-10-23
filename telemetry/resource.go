package telemetry

import (
	"github.com/mmcloughlin/pearl/log"
	"github.com/uber-go/tally"
	"go.uber.org/atomic"
)

// ResourceMetric records allocation and freeing of a resource.
type ResourceMetric interface {
	Alloc()
	Free()
}

// ResourceGauge counts and logs the number of a specific resource.
type ResourceGauge struct {
	count *atomic.Int64
	alloc tally.Counter
	free  tally.Counter
	gauge tally.Gauge
	log   log.Logger
}

// NewResourceMetric builds a new ResourceMetric recording stats on scope and
// logging to l.
func NewResourceMetric(scope tally.Scope, l log.Logger, name string) ResourceMetric {
	sub := scope.SubScope(name)
	return &ResourceGauge{
		count: atomic.NewInt64(0),
		alloc: sub.Counter("alloc"),
		free:  sub.Counter("free"),
		gauge: sub.Gauge("current"),
		log:   log.ForComponent(l, "resource_telemetry").With("resource_type", name),
	}
}

// Alloc records the addition of a resource.
func (r *ResourceGauge) Alloc() {
	r.log.Debug("allocate")
	r.alloc.Inc(1)
	r.gauge.Update(float64(r.count.Inc()))
}

// Free records a resource being freed.
func (r *ResourceGauge) Free() {
	r.log.Debug("free")
	r.free.Inc(1)
	v := r.count.Dec()
	if v < 0 {
		panic("negative resource count")
	}
	r.gauge.Update(float64(v))
}
