package utils

import (
	"testing"
	"time"
)

func TestInitialRTTSeedControlsProbesUntilMeasured(t *testing.T) {
	rtt := NewRTTStats()
	if got := rtt.PTO(false); got != 200*time.Millisecond {
		t.Fatalf("default probe timeout changed: %s", got)
	}
	rtt.SetInitialRTT(time.Second)
	if rtt.HasMeasurement() || rtt.PTO(false) != 2*time.Second {
		t.Fatalf("seed ignored or treated as a measurement: measured=%t PTO=%s", rtt.HasMeasurement(), rtt.PTO(false))
	}
	rtt.SetInitialRTT(0)
	if got := rtt.PTO(false); got != 2*time.Second {
		t.Fatalf("absent token estimate erased configured seed: %s", got)
	}
	rtt.UpdateRTT(10*time.Millisecond, 0)
	if !rtt.HasMeasurement() || rtt.SmoothedRTT() != 10*time.Millisecond || rtt.PTO(false) != 30*time.Millisecond {
		t.Fatalf("real measurement did not replace conservative seed: RTT=%s PTO=%s", rtt.SmoothedRTT(), rtt.PTO(false))
	}
	rtt.SetInitialRTT(2 * time.Second)
	if got := rtt.SmoothedRTT(); got != 10*time.Millisecond {
		t.Fatalf("later seed replaced a real measurement: %s", got)
	}
}

func TestNonpositiveInitialRTTLeavesDefaultIntact(t *testing.T) {
	for _, seed := range []time.Duration{0, -time.Second} {
		rtt := NewRTTStats()
		rtt.SetInitialRTT(seed)
		if rtt.SmoothedRTT() != DefaultInitialRTT || rtt.PTO(false) != 2*DefaultInitialRTT {
			t.Fatalf("invalid seed %s changed initial RTT/PTO: RTT=%s PTO=%s", seed, rtt.SmoothedRTT(), rtt.PTO(false))
		}
	}
}
