package telemetry

import (
	"runtime"
	"time"

	"github.com/uber-go/tally"
)

// ReportRuntime starts a loop updating runtime metrics once every interval.
func ReportRuntime(scope tally.Scope, interval time.Duration) {
	r := NewRuntime(scope)
	for _ = range time.Tick(interval) {
		r.Update()
	}
}

// Runtime reports goroutine and memory statistics exposed by the runtime package.
type Runtime struct {
	numGoroutines tally.Gauge
	heapAlloc     tally.Gauge
	heapIdle      tally.Gauge
	heapInuse     tally.Gauge
	heapObjects   tally.Gauge
	stackInuse    tally.Gauge
}

// NewRuntime constructs runtime metrics from the given scope.
func NewRuntime(scope tally.Scope) *Runtime {
	sub := scope.SubScope("runtime")
	memStat := func(name string) tally.Gauge {
		return sub.Tagged(map[string]string{"stat": name}).Gauge("memory")
	}
	return &Runtime{
		numGoroutines: sub.Gauge("goroutines"),
		heapAlloc:     memStat("heap_alloc"),
		heapIdle:      memStat("heap_idle"),
		heapInuse:     memStat("heap_inuse"),
		heapObjects:   memStat("heap_objects"),
		stackInuse:    memStat("stack_inuse"),
	}
}

// Update updates runtime stats.
func (r Runtime) Update() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	r.heapAlloc.Update(float64(mem.HeapAlloc))
	r.heapIdle.Update(float64(mem.HeapIdle))
	r.heapInuse.Update(float64(mem.HeapInuse))
	r.heapObjects.Update(float64(mem.HeapObjects))
	r.stackInuse.Update(float64(mem.StackInuse))

	r.numGoroutines.Update(float64(runtime.NumGoroutine()))
}
