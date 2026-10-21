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
			cfg := getQuicConfig(&quic.Config{InitialPacketSize: 1200, MaxPacketSize: ceiling})
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
			require.NoError(t, client.CloseWithError(0, ""))
			require.NoError(t, server.CloseWithError(0, ""))
			require.LessOrEqual(t, largest.Load(), int64(ceiling), "each observed UDP datagram, including probes, must obey the ceiling")
			require.GreaterOrEqual(t, largest.Load(), int64(1200))
		})
	}
}
