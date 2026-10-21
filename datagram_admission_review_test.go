package quic

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestDatagramAdmissionClosedSendersDoNotCopyOrSchedule(t *testing.T) {
	for _, full := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			var scheduled atomic.Int64
			queue := newDatagramQueue(func() { scheduled.Add(1) }, utils.DefaultLogger)
			conn := testTryDatagramConn(queue, 16383, 1200)
			if full {
				for range maxDatagramSendQueueLen {
					require.NoError(t, conn.SendDatagram([]byte("original")))
				}
			}
			queue.CloseWithError(assertTryCloseError)
			before := scheduled.Load()
			payload := make([]byte, 1000)
			for _, send := range []func([]byte) error{conn.SendDatagram, conn.TrySendDatagram} {
				allocs := testing.AllocsPerRun(100, func() {
					if err := send(payload); !errors.Is(err, assertTryCloseError) {
						panic(err)
					}
				})
				require.Zero(t, allocs)
			}
			require.Equal(t, before, scheduled.Load())
			for full && queue.Peek() != nil {
				require.Equal(t, []byte("original"), queue.Peek().Data)
				queue.Pop()
			}
			require.Nil(t, queue.Peek())
		})
	}
}

func TestDatagramAdmissionCallbacksCanCloseQueue(t *testing.T) {
	for _, useTry := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			var queue *datagramQueue
			queue = newDatagramQueue(func() {
				require.NotNil(t, queue.Peek())
				queue.CloseWithError(assertTryCloseError)
			}, utils.DefaultLogger)
			conn := testTryDatagramConn(queue, 16383, 1200)
			send := conn.SendDatagram
			if useTry {
				send = conn.TrySendDatagram
			}
			require.NoError(t, send([]byte("admission won before callback closed")))
			require.ErrorIs(t, send(nil), assertTryCloseError)
			queue.Pop()
			require.Nil(t, queue.Peek())
		})
	}
}

func TestDatagramAdmissionMixedProducersCloseAndOwnership(t *testing.T) {
	var admitted atomic.Int64
	queue := newDatagramQueue(func() { admitted.Add(1) }, utils.DefaultLogger)
	conn := testTryDatagramConn(queue, 16383, 1200)
	var producers sync.WaitGroup
	for i := range 16 {
		producers.Go(func() {
			send := conn.SendDatagram
			if i%2 == 0 {
				send = conn.TrySendDatagram
			}
			for range 64 {
				payload := []byte{byte(i)}
				err := send(payload)
				if err != nil && !errors.Is(err, ErrDatagramQueueFull) && !errors.Is(err, assertTryCloseError) {
					t.Error(err)
				}
				payload[0] = 255
			}
		})
	}
	var dequeued int64
	closed := false
	defer func() {
		if !closed {
			queue.CloseWithError(assertTryCloseError)
		}
	}()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	done := make(chan struct{})
	go func() { producers.Wait(); close(done) }()
	for {
		queue.sendMx.Lock()
		length := queue.sendQueue.Len()
		queue.sendMx.Unlock()
		require.LessOrEqual(t, length, maxDatagramSendQueueLen)
		if frame := queue.Peek(); frame != nil {
			require.Less(t, frame.Data[0], byte(16), "queue retained a caller's reusable buffer")
			queue.Pop()
			dequeued++
			if dequeued == 64 {
				queue.CloseWithError(assertTryCloseError)
				closed = true
			}
			continue
		}
		select {
		case <-timeout.C:
			t.Fatal("mixed producers did not drain or stop after queue closure")
		case <-done:
			if queue.Peek() != nil {
				continue
			}
			require.True(t, closed)
			require.Equal(t, admitted.Load(), dequeued)
			queue.sendMx.Lock()
			waiters := queue.sendWaiters
			queue.sendMx.Unlock()
			require.Zero(t, waiters)
			return
		default:
			runtime.Gosched()
		}
	}
}
