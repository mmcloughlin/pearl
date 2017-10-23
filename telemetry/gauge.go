package telemetry

import (
	"github.com/uber-go/tally"
	"go.uber.org/atomic"
)

// ResourceGauge counts and logs the number of a specific resource.
type ResourceGauge struct {
	count *atomic.Int64
	gauge tally.Gauge
}

// NewResourceGauge builds a new ResourceGauge publishing to the given metric.
func NewResourceGauge(g tally.Gauge) *ResourceGauge {
	return &ResourceGauge{
		count: atomic.NewInt64(0),
		gauge: g,
	}
}

// Add records the addition of a resource.
func (r *ResourceGauge) Add() {
	r.gauge.Update(float64(r.count.Inc()))
}

// Free records a resource being freed.
func (r *ResourceGauge) Free() {
	r.gauge.Update(float64(r.count.Dec()))
}
