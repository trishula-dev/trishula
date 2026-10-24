package bench

// Machine-factor sampling for the live run (TR-92a): one sample before
// and one after each budget-row pair. A sample runs a fixed calibration
// probe and reads the machine factor as wall time over CPU time on the
// probe block. CPU time stays with the work. Wall time absorbs the
// deschedule delay concurrent CI load adds. The ratio carries runner
// motion, not engine cost: the probe is fixed arithmetic work outside
// the CRS path, so an engine-side regression cannot inflate it, and the
// paired samples separate runner variance from code evidence.
import (
	"math"
	"time"
)

// probeReps is the rep count of one probe block. The block costs a few
// milliseconds, far above the CPU-time granularity the sample reads.
const probeReps = 64

// probeWork is the fixed calibration unit: 2048 sin+cos steps over
// varying input, deterministic, allocation-free, with no dependency on
// the CRS evaluator path. probeSink keeps the result live, so the
// compiler cannot elide the work.
var probeSink float64

func probeWork() {
	s := probeSink
	for i := 1; i <= 2048; i++ {
		s += math.Sin(float64(i)) * math.Cos(float64(i))
	}
	probeSink = s
}

// SampleMachineFactor samples the machine factor once. Both samples of
// a pair read 1.00 on a quiet host within noise; sustained concurrent
// CI load inflates the wall-clock side of the probe block. The sample
// clamps at 1.0: the budget comparison never divides below 1.0 on
// measurement noise. A host with no CPU-time counter (the platforms the
// project does not target) reads 1.00; hosted CI is the calibration
// surface and runs on unix.
func SampleMachineFactor() float64 {
	cpu0 := procCPU()
	t0 := time.Now()
	for i := 0; i < probeReps; i++ {
		probeWork()
	}
	wall := time.Since(t0)
	window := procCPU() - cpu0
	if wall <= 0 || window <= 0 {
		return 1
	}
	f := wall.Seconds() / window
	if f < 1 {
		return 1
	}
	return f
}
