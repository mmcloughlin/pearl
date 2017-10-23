// Package expvar reports tally metrics to expvar.
package expvar

import (
	"expvar"

	"github.com/uber-go/tally"
)

// reporter publishes metrics to expvar.
type reporter struct{}

// NewReporter builds a tally.CachedStatsReporter reporting to the expvar
// facility.
func NewReporter() tally.CachedStatsReporter {
	return reporter{}
}

// Capabilities returns the capabilities description of the reporter.
func (r reporter) Capabilities() tally.Capabilities {
	return r
}

// Reporting returns whether the reporter has the ability to actively report.
func (r reporter) Reporting() bool { return false }

// Tagging returns false, as expvar does not have tagging support.
func (r reporter) Tagging() bool { return false }

// AllocateCounter pre allocates a counter data structure backed by an
// expvar.Int. Tags are not supported.
func (r reporter) AllocateCounter(name string, _ map[string]string) tally.CachedCount {
	return counter{
		n: expvar.NewInt(name),
	}
}

type counter struct {
	n *expvar.Int
}

func (c counter) ReportCount(v int64) {
	c.n.Add(v)
}

// AllocateGauge pre allocates a gauge data structure backed by an expvar.Float.
// Tags are not supported.
func (r reporter) AllocateGauge(name string, _ map[string]string) tally.CachedGauge {
	return gauge{
		f: expvar.NewFloat(name),
	}
}

type gauge struct {
	f *expvar.Float
}

func (g gauge) ReportGauge(v float64) {
	g.f.Set(v)
}

// AllocateTimer is not implemented. Returns nil.
func (r reporter) AllocateTimer(name string, tags map[string]string) tally.CachedTimer {
	return nil
}

// AllocateHistogram is not implemented. Returns nil.
func (r reporter) AllocateHistogram(name string, tags map[string]string, buckets tally.Buckets) tally.CachedHistogram {
	return nil
}

// Flush is a no-op.
func (r reporter) Flush() {}
