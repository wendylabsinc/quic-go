package quic

import (
	"testing"
	"time"
)

func TestInitialRTTOptionSurvivesConfigPopulation(t *testing.T) {
	config := &Config{InitialRTT: time.Second}
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	if config.Clone().InitialRTT != time.Second || populateConfig(config).InitialRTT != time.Second {
		t.Fatal("configured RTT estimate was discarded")
	}
	if populateConfig(nil).InitialRTT != 0 {
		t.Fatal("default caller unexpectedly opted into a new RTT estimate")
	}
	if err := validateConfig(&Config{InitialRTT: -time.Second}); err == nil {
		t.Fatal("negative RTT estimate accepted")
	}
}
