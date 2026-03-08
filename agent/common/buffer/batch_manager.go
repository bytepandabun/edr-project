package buffer

import (
	"edr-project/agent/common/types"
	"sync"
	"time"
)

type BatchManager struct {
	buffer    *EventBuffer
	batchSize int
	interval  time.Duration
	onReady   func([]types.Event)
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

func NewBatchManager(buf *EventBuffer, size int, interval time.Duration, callback func([]types.Event)) *BatchManager {
	return &BatchManager{
		buffer:    buf,
		batchSize: size,
		interval:  interval,
		onReady:   callback,
		stopCh:    make(chan struct{}),
	}
}

func (m *BatchManager) Start() {
	m.wg.Add(1)
	go m.run()
}

func (m *BatchManager) run() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.flush()
		case <-m.stopCh:
			m.flush()
			return
		}
	}
}

func (m *BatchManager) flush() {
	if m.buffer.Size() == 0 {
		return
	}
	batch := m.buffer.GetBatch(m.batchSize)
	if len(batch) > 0 {
		m.onReady(batch)
	}
}

func (m *BatchManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}
