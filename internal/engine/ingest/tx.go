// Package ingest consumes shield events and assembles transactions
// (PRD §19.1 ingest sketch; TR-04). Kernel-free: the ringbuf reader is
// injected (TR-04b), maps come from the shield loader (TR-03).
package ingest

import (
	"sync"
	"time"
)

// Family discriminators on the tx layer mirror the #62 wire contract
// (shield.FamilyV4/V6 values 4/6 — duplicated here as the ingest-local
// ABI so the map/tx stay decoupled from the shield package's types).
const (
	FamilyV4 uint8 = 4
	FamilyV6 uint8 = 6
)

// FlowKey identifies one flow (5-tuple + family, defect #62: family is
// part of the key — a v4 address never aliases a v6 with the same tail).
type FlowKey struct {
	SrcIP   [4]byte  // v4; upper bytes must be zero for v4 flows
	SrcIP6  [16]byte // full address for v6 flows (network order)
	DstIP   [4]byte
	DstIP6  [16]byte
	SrcPort uint16
	DstPort uint16
	Family  uint8
}

// TxContext accumulates flow metadata + detection state for the ladder
// (TR-05). v0 carries the key + seen-first/seen-last mono timestamps.
type TxContext struct {
	Key      FlowKey
	FirstNS  uint64
	LastNS   uint64
	Packets  uint64
	Metadata map[string]string // event extras (path hints etc.), TR-04b fills
}

// TxManager owns the flow→tx table (§19.1 NoteFlow).
type TxManager struct {
	mu   sync.RWMutex
	txes map[FlowKey]*TxContext
	now  func() uint64 // monotonic ns, injectable for tests
}

// NewTxManager builds an empty manager on the wall monotonic clock.
func NewTxManager() *TxManager {
	return &TxManager{
		txes: make(map[FlowKey]*TxContext),
		now:  func() uint64 { return uint64(time.Now().UnixNano()) },
	}
}

// NoteFlow attaches flow metadata to a TX context: returns the existing
// tx for the key (idempotent) or creates one stamped now.
func (m *TxManager) NoteFlow(k FlowKey) *TxContext {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tx, ok := m.txes[k]; ok {
		tx.LastNS = m.now()
		tx.Packets++
		return tx
	}
	nowNS := m.now()
	tx := &TxContext{Key: k, FirstNS: nowNS, LastNS: nowNS, Packets: 1}
	m.txes[k] = tx
	return tx
}

// LookupFlow retrieves the live tx for a key (nil when absent/expired).
func (m *TxManager) LookupFlow(k FlowKey) *TxContext {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.txes[k]
}

// ExpireOlderThan evicts txes whose LastNS predates the cutoff
// (loader-clock nanoseconds). Returns the number evicted.
func (m *TxManager) ExpireOlderThan(cutoffNS uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, tx := range m.txes {
		if tx.LastNS < cutoffNS {
			delete(m.txes, k)
			n++
		}
	}
	return n
}

// Len reports the live tx count.
func (m *TxManager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txes)
}

// txFirstNS0 is a constructor-time helper (kept internal; the compiler
// folds it).
func txFirstNS0(m *TxManager) uint64 {
	return m.now()
}
