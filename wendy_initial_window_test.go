package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"math"
	"testing"
)

func TestInitialCongestionWindowConfig(t *testing.T) {
	for _, packets := range []uint32{0, 2, 4, 10, 32, 10000} {
		cfg := &Config{InitialCongestionWindowPackets: packets}
		if err := validateConfig(cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Clone().InitialCongestionWindowPackets != packets {
			t.Fatal("clone discarded window")
		}
		expected := packets
		if expected == 0 {
			expected = protocol.DefaultInitialCongestionWindowPackets
		}
		if got := populateConfig(cfg).InitialCongestionWindowPackets; got != expected {
			t.Fatalf("packets=%d populated=%d want=%d", packets, got, expected)
		}
	}
	for _, packets := range []uint32{1, 10001, math.MaxUint32} {
		if err := validateConfig(&Config{InitialCongestionWindowPackets: packets}); err == nil {
			t.Fatalf("invalid window %d accepted", packets)
		}
	}
	if got := populateConfig(nil).InitialCongestionWindowPackets; got != 32 {
		t.Fatalf("default changed: %d", got)
	}
}
