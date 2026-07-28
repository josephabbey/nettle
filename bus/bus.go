package bus

import (
	"context"
	"errors"
	"sync"
)

type Event any

type Bus interface {
	Publish(context.Context, Event) error
	Subscribe(buffer int) (<-chan Event, func())
	Close()
}

type Hub struct {
	mu     sync.RWMutex
	subs   map[uint64]chan Event
	nextID uint64
	closed bool
}

func NewHub() *Hub {
	return &Hub{subs: map[uint64]chan Event{}}
}

func (h *Hub) Publish(ctx context.Context, event Event) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return errors.New("bus closed")
	}
	subs := make([]chan Event, 0, len(h.subs))
	for _, sub := range h.subs {
		subs = append(subs, sub)
	}
	h.mu.RUnlock()

	for _, sub := range subs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sub <- event:
		}
	}
	return nil
}

func (h *Hub) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer <= 0 {
		buffer = 16
	}

	ch := make(chan Event, buffer)

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	id := h.nextID
	h.nextID++
	h.subs[id] = ch
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if sub, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(sub)
		}
		h.mu.Unlock()
	}

	return ch, unsubscribe
}

func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	for id, sub := range h.subs {
		delete(h.subs, id)
		close(sub)
	}
	h.mu.Unlock()
}
