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
