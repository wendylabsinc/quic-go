package ackhandler

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"testing"
	"time"
)

func TestConfiguredInitialWindowGrowsAndSurvivesMigration(t *testing.T) {
	for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		t.Run(perspective.String(), func(t *testing.T) {
			h := NewSentPacketHandler(0, 1200, 4, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, perspective, nil, utils.DefaultLogger).(*sentPacketHandler)
			now := monotime.Now()
			var packets packetTracker
			var pns []protocol.PacketNumber
			for range 4 {
				pn := h.PopPacketNumber(protocol.Encryption1RTT)
				pns = append(pns, pn)
				h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
			}
			if h.congestion.GetCongestionWindow() != 4800 || h.congestion.CanSend(h.bytesInFlight) {
				t.Fatalf("initial window did not bound four packets: %d, in flight=%d", h.congestion.GetCongestionWindow(), h.bytesInFlight)
			}
			_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			if h.congestion.GetCongestionWindow() <= 4800 {
				t.Fatal("configured initial window became a permanent cap")
			}
			h.MigratedPath(now.Add(20*time.Millisecond), 1350)
			if got := h.congestion.GetCongestionWindow(); got != 5400 {
				t.Fatalf("migration discarded configured window: %d", got)
			}
		})
	}
}
