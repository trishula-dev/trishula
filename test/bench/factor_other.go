//go:build !unix

package bench

// procCPU returns 0 where no self CPU-time counter exists (the platforms
// the project does not target). SampleMachineFactor clamps to factor
// 1.00 there; hosted CI is the calibration surface and runs on unix.
func procCPU() float64 {
	return 0
}
