package timing

import (
	"time"

	"golang.org/x/sys/unix"
)

// BootClock reads the Linux suspend-aware forwarding deadline clock.
func BootClock() time.Duration {
	var timestamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &timestamp); err != nil {
		panic("timing: read CLOCK_BOOTTIME: " + err.Error())
	}
	return time.Duration(timestamp.Nano())
}
