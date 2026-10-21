package quic

import (
	"fmt"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestConservativeDatagramCapacityFitsWorstShortHeader(t *testing.T) {
	for _, mtu := range []protocol.ByteCount{1200, 1280, 1400, 1452} {
		for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
			t.Run(fmt.Sprintf("%d/%d", mtu, version), func(t *testing.T) {
				body := estimateMaxPayloadSize(mtu)
				require.EqualValues(t, mtu-44, body)
				for _, cidLen := range []int{0, 20} {
					for _, pnLen := range []protocol.PacketNumberLen{1, 2, 3, 4} {
						header, err := wire.AppendShortHeader(nil, protocol.ParseConnectionID(make([]byte, cidLen)), 1, pnLen, protocol.KeyPhaseZero)
						require.NoError(t, err)
						frame := &wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, body)}
						packet, err := frame.Append(header, version)
						require.NoError(t, err)
						require.LessOrEqual(t, len(packet)+16, int(mtu))
						if cidLen == 20 && pnLen == 4 {
							frame.Data = append(frame.Data, 0)
							packet, err = frame.Append(header, version)
							require.NoError(t, err)
							require.Greater(t, len(packet)+16, int(mtu))
						}
					}
				}
			})
		}
	}
}

func readyCapacityConn(peer int64, estimate uint32) *Conn {
	c := testTryDatagramConn(newDatagramQueue(func() {}, utils.DefaultLogger), peer, estimate)
	c.handshakeCompleteChan = make(chan struct{})
	close(c.handshakeCompleteChan)
	return c
}

func TestCurrentDatagramCapacityValidationAndQueueIndependence(t *testing.T) {
	for _, tc := range []struct {
		peer int64
		want int64
	}{{2, 0}, {63, 61}, {64, 62}, {65, 63}, {66, 63}, {67, 64}, {16383, 1156}} {
		t.Run(fmt.Sprint(tc.peer), func(t *testing.T) {
			c := readyCapacityConn(tc.peer, 1156)
			got, err := c.CurrentMaxDatagramPayloadSize()
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			for range maxDatagramSendQueueLen {
				require.NoError(t, c.TrySendDatagram(make([]byte, got)))
			}
			got, err = c.CurrentMaxDatagramPayloadSize()
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.ErrorIs(t, c.TrySendDatagram(nil), ErrDatagramQueueFull)
			var sizeErr *DatagramTooLargeError
			require.ErrorAs(t, c.TrySendDatagram(make([]byte, got+1)), &sizeErr)
			require.Equal(t, got, sizeErr.MaxDatagramPayloadSize)
		})
	}
	c := readyCapacityConn(1, 1156)
	var sizeErr *DatagramTooLargeError
	_, err := c.CurrentMaxDatagramPayloadSize()
	require.ErrorAs(t, err, &sizeErr)
	require.EqualValues(t, -1, sizeErr.MaxDatagramPayloadSize)
	require.ErrorAs(t, c.TrySendDatagram(nil), &sizeErr)
	require.ErrorAs(t, c.SendDatagram(nil), &sizeErr)
	c.updateDatagramSendLimit(0)
	_, err = c.CurrentMaxDatagramPayloadSize()
	require.Error(t, err)
	c = readyCapacityConn(16383, 1156)
	c.handshakeCompleteChan = make(chan struct{})
	_, err = c.CurrentMaxDatagramPayloadSize()
	require.ErrorContains(t, err, "before handshake completion")
	c.datagramQueue.CloseWithError(assertTryCloseError)
	_, err = c.CurrentMaxDatagramPayloadSize()
	require.ErrorIs(t, err, assertTryCloseError)
	close(c.handshakeCompleteChan)
	_, err = c.CurrentMaxDatagramPayloadSize()
	require.ErrorIs(t, err, assertTryCloseError)
}

func TestCurrentDatagramCapacityConcurrentSnapshotsAndShrink(t *testing.T) {
	c := readyCapacityConn(16383, 1356)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				size, err := c.CurrentMaxDatagramPayloadSize()
				if err != nil || size < 0 || size > 1356 {
					t.Errorf("invalid capacity %d: %v", size, err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		for range 1000 {
			c.maxPayloadSizeEstimate.Store(1156)
			c.updateDatagramSendLimit(1200)
			c.maxPayloadSizeEstimate.Store(1356)
			c.updateDatagramSendLimit(16383)
		}
	})
	wg.Wait()
	old, err := c.CurrentMaxDatagramPayloadSize()
	require.NoError(t, err)
	c.maxPayloadSizeEstimate.Store(1156)
	var sizeErr *DatagramTooLargeError
	require.ErrorAs(t, c.TrySendDatagram(make([]byte, old)), &sizeErr)
	require.EqualValues(t, 1156, sizeErr.MaxDatagramPayloadSize)
	require.NoError(t, c.TrySendDatagram(make([]byte, 1100)))
	require.NoError(t, c.TrySendDatagram(nil))
}
