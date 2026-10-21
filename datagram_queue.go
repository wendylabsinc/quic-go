package quic

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
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
	sendWaiters int                // blocked Add callers have priority over TryAdd
	sendLimit   protocol.ByteCount // maximum DATAGRAM body; negative means unsupported
	sendEpoch   uint64             // queued and blocked 0-RTT sends cannot cross a rejection
	sendChanged chan struct{}      // broadcasts capability changes and 0-RTT rejection
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
		hasData:     hasData,
		sendLimit:   protocol.MaxByteCount,
		sendChanged: make(chan struct{}),
		rcvd:        make(chan struct{}, 1),
		sent:        make(chan struct{}, 1),
		closed:      make(chan struct{}),
		logger:      logger,
	}
}

// sendError is called with sendMx held. It revalidates admission after any
// wait: a copied or blocked DATAGRAM must not cross a 0-RTT rejection or newly
// applicable peer limits.
func (h *datagramQueue) sendError(size int, maxPayload protocol.ByteCount, epoch uint64) error {
	select {
	case <-h.closed:
		return h.closeErr
	default:
	}
	if epoch != h.sendEpoch {
		return Err0RTTRejected
	}
	if h.sendLimit < 0 {
		return errors.New("datagram support disabled")
	}
	limit := min(h.sendLimit, maxPayload)
	if protocol.ByteCount(size) > limit {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(limit)}
	}
	return nil
}

// PrepareSend validates before a blocking sender copies its payload and captures
// the early-data epoch, including callers not yet inside Add when 0-RTT fails.
func (h *datagramQueue) PrepareSend(size int, maxPayload protocol.ByteCount) (uint64, error) {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return h.sendEpoch, h.sendError(size, maxPayload, h.sendEpoch)
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	epoch, err := h.PrepareSend(len(f.Data), protocol.MaxByteCount)
	if err != nil {
		return err
	}
	return h.add(f, epoch)
}

func (h *datagramQueue) add(f *wire.DatagramFrame, epoch uint64) error {
	h.sendMx.Lock()
	waiting := false
	for {
		if err := h.sendError(len(f.Data), protocol.MaxByteCount, epoch); err != nil {
			if waiting {
				h.sendWaiters--
			}
			h.sendMx.Unlock()
			return err
		}
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
		case <-h.sent:
		default:
		}
		changed := h.sendChanged
		h.sendMx.Unlock()
		select {
		case <-h.closed:
		case <-h.sent:
		case <-changed:
		}
		h.sendMx.Lock()
	}
}

// TryAdd copies and queues a DATAGRAM without waiting for send-queue space.
// Admission, peer-limit publication, early-data rejection and closure are
// serialized by sendMx. Existing blocked Add callers reserve free capacity.
func (h *datagramQueue) TryAdd(p []byte, maxPayload protocol.ByteCount) error {
	h.sendMx.Lock()
	if err := h.sendError(len(p), maxPayload, h.sendEpoch); err != nil {
		h.sendMx.Unlock()
		return err
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

// SetSendLimit publishes the newly applicable peer DATAGRAM body limit and
// removes frames that no longer fit. All blocked admissions revalidate it.
func (h *datagramQueue) SetSendLimit(limit protocol.ByteCount) {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	h.sendLimit = limit
	for range h.sendQueue.Len() {
		f := h.sendQueue.PopFront()
		if limit >= 0 && protocol.ByteCount(len(f.Data)) <= limit {
			h.sendQueue.PushBack(f)
		}
	}
	close(h.sendChanged)
	h.sendChanged = make(chan struct{})
}

// Reject0RTT discards every queued early DATAGRAM, even when the new peer limits
// are identical. Such data must not be replayed into the reset application.
func (h *datagramQueue) Reject0RTT() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	h.sendEpoch++
	h.sendLimit = protocol.InvalidByteCount
	h.sendQueue.Clear()
	close(h.sendChanged)
	h.sendChanged = make(chan struct{})
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
