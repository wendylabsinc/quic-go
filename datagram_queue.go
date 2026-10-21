package quic

import (
	"bytes"
	"context"
	"sync"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

type datagramQueue struct {
	sendMx      sync.Mutex
	sendWaiters int // blocked Add callers have priority over TryAdd
	sendQueue   ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent        chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()
	waiting := false

	for {
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			if waiting {
				h.sendWaiters--
			}
			h.sendQueue.PushBack(f)
			// Pop notifications can coalesce while several slots become free.
			// Pass available capacity to another blocked sender before TryAdd
			// may use it.
			if h.sendWaiters > 0 && h.sendQueue.Len() < maxDatagramSendQueueLen {
				select {
				case h.sent <- struct{}{}:
				default:
				}
			}
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		if !waiting {
			h.sendWaiters++
			waiting = true
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			h.sendMx.Lock()
			h.sendWaiters--
			h.sendMx.Unlock()
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// TryAdd copies and queues a DATAGRAM without waiting for send-queue space.
// Admission and closure are serialized by sendMx. Existing blocked Add callers
// reserve available capacity, so repeated TryAdd calls cannot starve them.
func (h *datagramQueue) TryAdd(p []byte) error {
	h.sendMx.Lock()
	select {
	case <-h.closed:
		h.sendMx.Unlock()
		return h.closeErr
	default:
	}
	if h.sendWaiters > 0 || h.sendQueue.Len() >= maxDatagramSendQueueLen {
		h.sendMx.Unlock()
		return ErrDatagramQueueFull
	}
	h.sendQueue.PushBack(&wire.DatagramFrame{DataLenPresent: true, Data: bytes.Clone(p)})
	h.sendMx.Unlock()
	h.hasData()
	return nil
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	h.closeErr = e
	close(h.closed)
}
