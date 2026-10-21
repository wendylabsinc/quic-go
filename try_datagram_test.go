package quic

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func testTryDatagramConn(queue *datagramQueue, peerMax int64, packetEstimate uint32) *Conn {
	c := &Conn{datagramQueue: queue, version: protocol.Version1}
	c.peerMaxDatagramFrameSize.Store(peerMax)
	c.maxPayloadSizeEstimate.Store(packetEstimate)
	return c
}

func TestTrySendDatagramValidationAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		peerMax  int64
		estimate uint32
		want     int
	}{{2, 1000, 0}, {63, 1000, 61}, {65, 1000, 63}, {66, 1000, 63}, {67, 1000, 64}, {100, 1000, 97}, {2000, 1000, 1000}} {
		t.Run(fmt.Sprintf("%d/%d", tc.peerMax, tc.estimate), func(t *testing.T) {
			queue := newDatagramQueue(func() {}, utils.DefaultLogger)
			c := testTryDatagramConn(queue, tc.peerMax, tc.estimate)
			var sizeErr *DatagramTooLargeError
			require.ErrorAs(t, c.TrySendDatagram(make([]byte, tc.want+1)), &sizeErr)
			require.EqualValues(t, tc.want, sizeErr.MaxDatagramPayloadSize)
			require.Nil(t, queue.Peek())
			p := bytes.Repeat([]byte{42}, tc.want)
			require.NoError(t, c.TrySendDatagram(p))
			clear(p)
			require.True(t, queue.Peek().DataLenPresent)
			require.Equal(t, bytes.Repeat([]byte{42}, tc.want), queue.Peek().Data)
			queue.Pop()
			require.Nil(t, queue.Peek())
		})
	}
	// No peer parameters have been published yet. This is safe before the
	// handshake and does not dereference the handshake-owned peerParams.
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	c := testTryDatagramConn(queue, 0, 1200)
	for _, limit := range []int64{0, -1} {
		c.peerMaxDatagramFrameSize.Store(limit)
		require.Error(t, c.TrySendDatagram(nil))
		require.Nil(t, queue.Peek())
	}
}

func TestTrySendDatagramFullAndClosedDoNotAllocate(t *testing.T) {
	var signals int
	queue := newDatagramQueue(func() { signals++ }, utils.DefaultLogger)
	c := testTryDatagramConn(queue, 16383, 1200)
	for range maxDatagramSendQueueLen {
		require.NoError(t, c.TrySendDatagram([]byte("queued")))
	}
	payload := make([]byte, 1000)
	allocs := testing.AllocsPerRun(100, func() {
		if err := c.TrySendDatagram(payload); !errors.Is(err, ErrDatagramQueueFull) {
			panic(err)
		}
	})
	require.Zero(t, allocs)
	require.Equal(t, maxDatagramSendQueueLen, signals)
	for range maxDatagramSendQueueLen {
		require.Equal(t, []byte("queued"), queue.Peek().Data)
		queue.Pop()
	}
	// The callback may acquire sendMx, proving admission released it first.
	queue.hasData = func() { require.NotNil(t, queue.Peek()) }
	require.NoError(t, c.TrySendDatagram(nil))
	require.Empty(t, queue.Peek().Data)
	queue.Pop()
	queue.CloseWithError(assertTryCloseError)
	allocs = testing.AllocsPerRun(100, func() {
		if err := c.TrySendDatagram(payload); !errors.Is(err, assertTryCloseError) {
			panic(err)
		}
	})
	require.Zero(t, allocs)
	require.Nil(t, queue.Peek())
}

var assertTryCloseError = errors.New("test connection closed")

func TestTryDatagramPreservesBlockedSenders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)
		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.TryAdd([]byte("original")))
		}
		const waiters = 3
		results := make(chan error, waiters)
		for range waiters {
			go func() { results <- queue.Add(&wire.DatagramFrame{Data: []byte("blocking")}) }()
		}
		synctest.Wait()
		// Several pops happen without allowing the blocked producers to run.
		// Try must not consume the free slots reserved for those producers.
		for range waiters {
			queue.Pop()
			require.ErrorIs(t, queue.TryAdd([]byte("overtake")), ErrDatagramQueueFull)
		}
		synctest.Wait()
		for range waiters {
			select {
			case err := <-results:
				require.NoError(t, err)
			default:
				t.Fatal("blocked SendDatagram did not receive available capacity")
			}
		}
		for range maxDatagramSendQueueLen - waiters {
			require.Equal(t, []byte("original"), queue.Peek().Data)
			queue.Pop()
		}
		for range waiters {
			require.Equal(t, []byte("blocking"), queue.Peek().Data)
			queue.Pop()
		}
		require.NoError(t, queue.TryAdd([]byte("later")))
	})
}

func TestTryDatagramCloseAdmissionRace(t *testing.T) {
	for range 100 {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)
		start := make(chan struct{})
		result := make(chan error, 1)
		go func() { <-start; result <- queue.TryAdd([]byte("racing")) }()
		close(start)
		queue.CloseWithError(assertTryCloseError)
		err := <-result
		if err == nil {
			require.Equal(t, []byte("racing"), queue.Peek().Data)
			queue.Pop()
		} else {
			require.ErrorIs(t, err, assertTryCloseError)
		}
		require.ErrorIs(t, queue.TryAdd(nil), assertTryCloseError)
		require.Nil(t, queue.Peek())
	}
}

func TestTryDatagramConcurrentProducersAndParameterUpdates(t *testing.T) {
	var admitted, dequeued atomic.Int64
	queue := newDatagramQueue(func() { admitted.Add(1) }, utils.DefaultLogger)
	c := testTryDatagramConn(queue, 16383, 1200)
	var producers sync.WaitGroup
	for i := range 16 {
		producers.Go(func() {
			for range 100 {
				p := []byte{byte(i)}
				if err := c.TrySendDatagram(p); err != nil && !errors.Is(err, ErrDatagramQueueFull) {
					t.Error(err)
				}
				p[0] = 255
			}
		})
	}
	updatesDone := make(chan struct{})
	go func() {
		defer close(updatesDone)
		for range 1000 {
			c.peerMaxDatagramFrameSize.Store(2000)
			c.peerMaxDatagramFrameSize.Store(16383)
		}
	}()
	producersDone := make(chan struct{})
	go func() { producers.Wait(); close(producersDone) }()
	for {
		queue.sendMx.Lock()
		require.LessOrEqual(t, queue.sendQueue.Len(), maxDatagramSendQueueLen)
		queue.sendMx.Unlock()
		if f := queue.Peek(); f != nil {
			require.Less(t, f.Data[0], byte(16))
			queue.Pop()
			dequeued.Add(1)
			continue
		}
		select {
		case <-producersDone:
			<-updatesDone
			// Producers have completed their callbacks, and no frame remains.
			if queue.Peek() == nil {
				require.Equal(t, admitted.Load(), dequeued.Load())
				return
			}
		default:
			runtime.Gosched()
		}
	}
}
