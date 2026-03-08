package buffer

import (
	"edr-project/agent/common/types"
	"sync"
)

type EventBuffer struct {
	events []types.Event
	mu     sync.Mutex
	max    int
}

func NewEventBuffer(size int) *EventBuffer {
	return &EventBuffer{
		events: make([]types.Event, 0, size),
		max:    size,
	}
}

func (b *EventBuffer) Push(e types.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) < b.max {
		b.events = append(b.events, e)
	}
}

func (b *EventBuffer) GetBatch(size int) []types.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := size
	if len(b.events) < size {
		count = len(b.events)
	}
	batch := make([]types.Event, count)
	copy(batch, b.events[:count])
	b.events = b.events[count:]
	return batch
}

func (b *EventBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}
