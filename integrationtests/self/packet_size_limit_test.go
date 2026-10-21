package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/stretchr/testify/require"
)

func TestMaxPacketSizeOnUDPWire(t *testing.T) {
	for _, ceiling := range []uint16{1200, 1400} {
		t.Run(fmt.Sprint(ceiling), func(t *testing.T) {
			cfg := getQuicConfig(&quic.Config{InitialPacketSize: 1200, MaxPacketSize: ceiling, EnableDatagrams: true})
			ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), cfg)
			require.NoError(t, err)
			defer ln.Close()
			var largest atomic.Int64
			proxy := &quicproxy.Proxy{
				Conn: newUDPConnLocalhost(t), ServerAddr: ln.Addr().(*net.UDPAddr),
				DropPacket: func(_ quicproxy.Direction, _, _ net.Addr, p []byte) bool {
					for {
						old := largest.Load()
						if int64(len(p)) <= old || largest.CompareAndSwap(old, int64(len(p))) {
							break
						}
					}
					return false
				},
				DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return time.Millisecond },
			}
			require.NoError(t, proxy.Start())
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := quic.Dial(ctx, newUDPConnLocalhost(t), proxy.LocalAddr(), getTLSClientConfig(), cfg)
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			server, err := ln.Accept(ctx)
			require.NoError(t, err)
			defer server.CloseWithError(0, "")
			done := make(chan error, 1)
			go func() {
				str, err := server.AcceptStream(ctx)
				if err != nil {
					done <- err
					return
				}
				_, err = io.Copy(io.Discard, str)
				done <- err
			}()
			str, err := client.OpenStream()
			require.NoError(t, err)
			_, err = str.Write(PRDataLong)
			require.NoError(t, err)
			require.NoError(t, str.Close())
			require.NoError(t, <-done)
			if ceiling > 1200 {
				require.Eventually(t, func() bool { return largest.Load() >= int64(ceiling)-21 }, 2*time.Second, 2*time.Millisecond, "PMTU must grow above initial size without crossing the cap")
			}
			capacity, err := client.CurrentMaxDatagramPayloadSize()
			require.NoError(t, err)
			require.GreaterOrEqual(t, capacity, int64(1156))
			require.LessOrEqual(t, capacity, int64(ceiling)-44)
			if ceiling > 1200 {
				require.GreaterOrEqual(t, capacity, int64(1329), "validated path must carry the complete carrier body")
			}
			var sizeErr *quic.DatagramTooLargeError
			require.ErrorAs(t, client.TrySendDatagram(make([]byte, int64(ceiling)-43)), &sizeErr)
			require.NoError(t, client.TrySendDatagram(make([]byte, capacity)))
			body, err := server.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Len(t, body, int(capacity))
			require.NoError(t, client.CloseWithError(0, ""))
			require.NoError(t, server.CloseWithError(0, ""))
			require.LessOrEqual(t, largest.Load(), int64(ceiling), "each observed UDP datagram, including probes, must obey the ceiling")
			require.GreaterOrEqual(t, largest.Load(), int64(1200))
		})
	}
}

// A new path must start from its conservative baseline, rather than inheriting
// the old path's successful PMTU probes. Public address/capacity queries run
// throughout the switch, exercising publication to concurrent application code.
func TestDatagramCapacityResetsOnMigration(t *testing.T) {
	cfg := getQuicConfig(&quic.Config{InitialPacketSize: 1200, MaxPacketSize: 1400, EnableDatagrams: true})
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), cfg)
	require.NoError(t, err)
	defer ln.Close()
	tr1 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr1.Close()
	tr2 := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr2.Close()
	var constrained atomic.Bool
	proxy := &quicproxy.Proxy{Conn: newUDPConnLocalhost(t), ServerAddr: ln.Addr().(*net.UDPAddr),
		DropPacket:  func(_ quicproxy.Direction, _, _ net.Addr, p []byte) bool { return constrained.Load() && len(p) > 1200 },
		DelayPacket: func(quicproxy.Direction, net.Addr, net.Addr, []byte) time.Duration { return time.Millisecond },
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := tr1.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), cfg)
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	transfer := func() {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			s, e := server.AcceptUniStream(ctx)
			if e == nil {
				_, e = io.Copy(io.Discard, s)
			}
			done <- e
		}()
		s, e := client.OpenUniStream()
		require.NoError(t, e)
		_, e = s.Write(PRDataLong)
		require.NoError(t, e)
		require.NoError(t, s.Close())
		require.NoError(t, <-done)
	}
	transfer()
	require.Eventually(t, func() bool { n, e := client.CurrentMaxDatagramPayloadSize(); return e == nil && n >= 1329 }, 2*time.Second, time.Millisecond)
	path, err := client.AddPath(tr2)
	require.NoError(t, err)
	require.NoError(t, path.Probe(ctx))
	constrained.Store(true)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				client.LocalAddr()
				client.RemoteAddr()
				client.CurrentMaxDatagramPayloadSize()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	require.NoError(t, path.Switch())
	require.Eventually(t, func() bool { return client.LocalAddr().String() == tr2.Conn.LocalAddr().String() }, time.Second, time.Millisecond)
	capacity, err := client.CurrentMaxDatagramPayloadSize()
	require.NoError(t, err)
	require.EqualValues(t, 1156, capacity)
	var sizeErr *quic.DatagramTooLargeError
	require.ErrorAs(t, client.TrySendDatagram(make([]byte, 1329)), &sizeErr)
	require.NoError(t, client.TrySendDatagram(make([]byte, 1100)))
	body, err := server.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Len(t, body, 1100)
	transfer()
}
