//go:build unix

package bench

// procCPU reads the CPU time the process consumed since start (user +
// system, seconds), from the getrusage self counters. The delta between
// two reads bounds one probe block.
import "syscall"

func procCPU() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	u := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
	s := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	return u + s
}
