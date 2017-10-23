// Package logging reports tally metrics to a logger.
package logging

import (
	"github.com/mmcloughlin/pearl/log"

	"github.com/uber-go/tally"
)

// metricLogger adds tags to a logger to report the given metric.
func metricLogger(l log.Logger, name, metricType string, tags map[string]string) log.Logger {
	return log.WithTags(l, tags).With("metric_name", name).With("metric_type", metricType)
}

// reporter publishes metrics to a logger.
type reporter struct {
	l log.Logger
}

// NewReporter builds a tally.CachedStatsReporter reporting metrics to the given
// logger.
func NewReporter(l log.Logger) tally.CachedStatsReporter {
	return reporter{
		l: log.ForComponent(l, "metrics"),
	}
}

// Capabilities returns the capabilities description of the reporter.
func (r reporter) Capabilities() tally.Capabilities {
	return r
}

// Reporting returns whether the reporter has the ability to actively report.
func (r reporter) Reporting() bool { return false }

// Tagging returns true.
func (r reporter) Tagging() bool { return true }

// AllocateCounter pre allocates a counter logger.
func (r reporter) AllocateCounter(name string, tags map[string]string) tally.CachedCount {
	return counter{
		l: metricLogger(r.l, name, "counter", tags),
	}
}

type counter struct {
	l log.Logger
}

func (c counter) ReportCount(v int64) {
	c.l.With("value", v).Debug("report counter")
}

// AllocateGauge pre allocates a gauge logger.
func (r reporter) AllocateGauge(name string, tags map[string]string) tally.CachedGauge {
	return gauge{
		l: metricLogger(r.l, name, "gauge", tags),
	}
}

type gauge struct {
	l log.Logger
}

func (g gauge) ReportGauge(v float64) {
	g.l.With("value", v).Debug("report gauge")
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
