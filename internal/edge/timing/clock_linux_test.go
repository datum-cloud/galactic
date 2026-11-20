package timing

import "testing"

func TestBootClock(t *testing.T) {
	if now, later := BootClock(), BootClock(); later < now {
		t.Errorf("CLOCK_BOOTTIME went back from %v to %v", now, later)
	}
}
