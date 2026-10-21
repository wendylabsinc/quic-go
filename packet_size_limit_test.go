package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMaxPacketSizeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		initial, ceiling         uint16
		wantInitial, wantCeiling uint16
		invalid                  bool
	}{
		{"defaults", 0, 0, 1280, 1452, false},
		{"minimum", 0, 1200, 1200, 1200, false},
		{"bounded default", 0, 1400, 1280, 1400, false},
		{"safe baseline", 1200, 1400, 1200, 1400, false},
		{"explicit equal", 1400, 1400, 1400, 1400, false},
		{"upper bound", 1452, 1452, 1452, 1452, false},
		{"legacy normalization", 10, 0, 1200, 1452, false},
		{"legacy upper normalization", 65535, 0, 1452, 1452, false},
		{"bounded upper normalization", 65535, 1452, 1452, 1452, false},
		{"normalized initial conflict", 65535, 1400, 0, 0, true},
		{"bounded normalization", 10, 1200, 1200, 1200, false},
		{"too small", 0, 1199, 0, 0, true},
		{"too large", 0, 1453, 0, 0, true},
		{"initial conflict", 1280, 1200, 0, 0, true},
		{"explicit initial conflict", 1452, 1400, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{InitialPacketSize: tc.initial, MaxPacketSize: tc.ceiling}
			err := validateConfig(cfg)
			if tc.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			populated := populateConfig(cfg)
			require.Equal(t, tc.wantInitial, populated.InitialPacketSize)
			require.Equal(t, tc.wantCeiling, populated.MaxPacketSize)
			require.Equal(t, populated.MaxPacketSize, populated.Clone().MaxPacketSize)
		})
	}
}

func TestPathMTUBoundsRespectCeilingAndDiscoveryMode(t *testing.T) {
	for _, tc := range []struct {
		name               string
		initial, ceiling   uint16
		peer               protocol.ByteCount
		df, disabled       bool
		wantStart, wantMax protocol.ByteCount
	}{
		{"local cap", 1200, 1400, 1452, true, false, 1200, 1400},
		{"peer cap", 1200, 1400, 1280, true, false, 1200, 1280},
		{"peer lowers baseline", 1280, 1400, 1200, true, false, 1200, 1200},
		{"no DF", 1200, 1400, 1452, false, false, 1200, 1200},
		{"disabled", 1200, 1400, 1452, true, true, 1200, 1200},
		{"default cap", 1280, 0, 0, true, false, 1280, 1452},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{config: populateConfig(&Config{InitialPacketSize: tc.initial, MaxPacketSize: tc.ceiling, DisablePathMTUDiscovery: tc.disabled}), peerParams: &wire.TransportParameters{MaxUDPPayloadSize: tc.peer}}
			start, max := c.pathMTUBounds(tc.df)
			require.Equal(t, tc.wantStart, start)
			require.Equal(t, tc.wantMax, max)
			finder := newMTUDiscoverer(&utils.RTTStats{}, start, max, nil)
			now := monotime.Now()
			finder.Start(now)
			finder.Reset(now, start, max)
			if !tc.df || tc.disabled || start == max {
				require.False(t, finder.ShouldSendProbe(now.Add(time.Hour)), "reset must not enable discovery")
			} else {
				require.True(t, finder.ShouldSendProbe(now.Add(time.Hour)))
				_, size := finder.GetPing(now.Add(time.Hour))
				require.LessOrEqual(t, size, tc.wantMax)
			}
		})
	}
}
