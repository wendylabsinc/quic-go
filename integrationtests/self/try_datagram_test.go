package self_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestTrySendDatagramUDP(t *testing.T) {
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
	require.NoError(t, err)
	defer client.CloseWithError(0, "")
	server, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer server.CloseWithError(0, "")
	for _, pair := range [][2]*quic.Conn{{client, server}, {server, client}} {
		for _, p := range [][]byte{nil, []byte("try datagram"), bytes.Repeat([]byte{42}, 1000)} {
			require.NoError(t, pair[0].TrySendDatagram(p))
			got, err := pair[1].ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, string(p), string(got))
		}
	}
	var sizeErr *quic.DatagramTooLargeError
	require.ErrorAs(t, client.TrySendDatagram(make([]byte, 65507)), &sizeErr)
	require.Positive(t, sizeErr.MaxDatagramPayloadSize)
	require.NoError(t, client.CloseWithError(42, "closed"))
	var closeErr *quic.ApplicationError
	require.ErrorAs(t, client.TrySendDatagram(nil), &closeErr)
	require.EqualValues(t, 42, closeErr.ErrorCode)
}

func TestTrySendDatagramCongestionAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 10 * time.Millisecond
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, rtt)
		defer closeFn(t)
		ln, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
		require.NoError(t, err)
		defer ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client, err := quic.Dial(ctx, clientPacketConn, ln.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
		require.NoError(t, err)
		defer client.CloseWithError(0, "")
		server, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer server.CloseWithError(0, "")
		payload := make([]byte, 1000)
		full := false
		for range 10000 {
			if err := client.TrySendDatagram(payload); errors.Is(err, quic.ErrDatagramQueueFull) {
				full = true
				break
			} else {
				require.NoError(t, err)
			}
		}
		require.True(t, full, "congestion-limited sender must reach bounded admission")
		// Reliable streams still progress once ACKs release congestion credit.
		str, err := client.OpenStream()
		require.NoError(t, err)
		_, err = str.Write([]byte("control survives queue saturation"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		incoming, err := server.AcceptStream(ctx)
		require.NoError(t, err)
		got, err := io.ReadAll(incoming)
		require.NoError(t, err)
		require.Equal(t, "control survives queue saturation", string(got))
		// This Try is admitted after transport progress, independently of
		// whether the receiver retained every earlier unreliable frame.
		time.Sleep(10 * rtt)
		require.NoError(t, client.TrySendDatagram([]byte("later")))
	})
}

func TestTrySendDatagram0RTT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
		defer closeFn(t)
		tr := &quic.Transport{Conn: serverPacketConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true, Allow0RTT: true}))
		require.NoError(t, err)
		defer ln.Close()
		clientTLS := dialAndReceiveTicket(t, ln, clientPacketConn, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client, err := quic.DialEarly(ctx, clientPacketConn, ln.Addr(), clientTLS, getQuicConfig(&quic.Config{EnableDatagrams: true}))
		require.NoError(t, err)
		defer client.CloseWithError(0, "")
		require.False(t, client.ConnectionState().TLS.HandshakeComplete)
		require.NoError(t, client.TrySendDatagram([]byte("early")))
		select {
		case <-client.HandshakeComplete():
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		server, err := ln.Accept(ctx)
		require.NoError(t, err)
		defer server.CloseWithError(0, "")
		require.True(t, client.ConnectionState().Used0RTT)
		got, err := server.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, "early", string(got))
	})
}

func TestTrySendDatagramRejected0RTT(t *testing.T) {
	for _, mode := range []string{"same limit", "disabled", "smaller limit"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, 10*time.Millisecond)
				defer closeFn(t)
				tr := &quic.Transport{Conn: serverPacketConn}
				defer tr.Close()
				tlsConf := getTLSConfig()
				ln, err := tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{EnableDatagrams: true, Allow0RTT: true}))
				require.NoError(t, err)
				clientTLS := dialAndReceiveTicket(t, ln, clientPacketConn, nil)
				require.NoError(t, ln.Close())
				time.Sleep(time.Hour)
				synctest.Wait()
				if mode == "smaller limit" {
					original := wire.MaxDatagramSize
					wire.MaxDatagramSize = 456
					defer func() { wire.MaxDatagramSize = original }()
				}
				ln, err = tr.ListenEarly(tlsConf, getQuicConfig(&quic.Config{EnableDatagrams: mode != "disabled", Allow0RTT: false}))
				require.NoError(t, err)
				defer ln.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, err := quic.DialEarly(ctx, clientPacketConn, ln.Addr(), clientTLS, getQuicConfig(&quic.Config{EnableDatagrams: true}))
				require.NoError(t, err)
				defer client.CloseWithError(0, "")
				require.False(t, client.ConnectionState().TLS.HandshakeComplete)
				// Quiesce the current fake instant, then fill past the initial
				// congestion window. Future ACKs/handshake packets cannot arrive
				// until this test allows simulated time to advance.
				synctest.Wait()
				full := false
				for range 10000 {
					err := client.TrySendDatagram(make([]byte, 1000))
					if errors.Is(err, quic.ErrDatagramQueueFull) {
						full = true
						break
					}
					require.NoError(t, err)
				}
				require.True(t, full)
				synctest.Wait()
				for range 10000 {
					err := client.TrySendDatagram(make([]byte, 1000))
					if errors.Is(err, quic.ErrDatagramQueueFull) {
						break
					}
					require.NoError(t, err)
				}
				blocked := make(chan error, 1)
				go func() { blocked <- client.SendDatagram(make([]byte, 1000)) }()
				synctest.Wait()
				select {
				case err := <-blocked:
					t.Fatalf("expected blocked sender, got %v", err)
				default:
				}
				select {
				case <-client.HandshakeComplete():
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				// An Initial ACK can release a slot just before rejection. In
				// that order admission wins; otherwise the waiter is rejected.
				// In both cases its early bytes must never be replayed.
				if err := <-blocked; err != nil {
					require.ErrorIs(t, err, quic.Err0RTTRejected)
				}
				client, err = client.NextConnection(ctx)
				require.NoError(t, err)
				require.False(t, client.ConnectionState().Used0RTT)
				server, err := ln.Accept(ctx)
				require.NoError(t, err)
				defer server.CloseWithError(0, "")
				if mode == "disabled" {
					require.Error(t, client.TrySendDatagram(nil))
					require.Error(t, client.SendDatagram(nil))
				} else {
					require.NoError(t, client.TrySendDatagram([]byte("only fresh data")))
					got, err := server.ReceiveDatagram(ctx)
					require.NoError(t, err)
					require.Equal(t, "only fresh data", string(got))
				}
				str, err := client.OpenStream()
				require.NoError(t, err)
				_, err = str.Write([]byte("still connected"))
				require.NoError(t, err)
				require.NoError(t, str.Close())
				incoming, err := server.AcceptStream(ctx)
				require.NoError(t, err)
				got, err := io.ReadAll(incoming)
				require.NoError(t, err)
				require.Equal(t, "still connected", string(got))
			})
		})
	}
}
