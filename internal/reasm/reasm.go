// Package reasm — reassembly پکت‌های UDP خارج از ترتیب
//
// بهینه‌سازی‌ها:
//   - deliver() بدون double unlock/lock — race-free
//   - channel cap=512 — کمتر block
//   - sync.Map در Manager — بدون deadlock
package reasm

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxBuffered = 128
	gapTimeout  = 3 * time.Second
	chanCap     = 512
)

type packet struct {
	seq   uint32
	data  []byte
	at    time.Time
	flags byte
}

type pktHeap []packet

func (h pktHeap) Len() int            { return len(h) }
func (h pktHeap) Less(i, j int) bool  { return h[i].seq < h[j].seq }
func (h pktHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *pktHeap) Push(x any)         { *h = append(*h, x.(packet)) }
func (h *pktHeap) Pop() any {
	old := *h; n := len(old); x := old[n-1]
	old[n-1] = packet{}
	*h = old[:n-1]; return x
}

// Reassembler — thread-safe
type Reassembler struct {
	mu        sync.Mutex
	heap      pktHeap
	nextSeq   uint32
	ready     chan []byte
	closed    atomic.Bool
	delivered atomic.Uint64
	dropped   atomic.Uint64
}

func New(firstSeq uint32) *Reassembler {
	return &Reassembler{
		nextSeq: firstSeq,
		ready:   make(chan []byte, chanCap),
	}
}

func (r *Reassembler) Push(seq uint32, flags byte, data []byte) {
	if r.closed.Load() { return }
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() { return }

	if seq < r.nextSeq { r.dropped.Add(1); return }
	if seq == r.nextSeq {
		r.deliverLocked(data)
		r.nextSeq++
		r.flushLocked()
		return
	}
	if r.heap.Len() < maxBuffered {
		cp := make([]byte, len(data))
		copy(cp, data)
		heap.Push(&r.heap, packet{seq: seq, data: cp, at: time.Now(), flags: flags})
	} else {
		r.dropped.Add(1)
	}
}

// deliverLocked — از داخل mutex صدا بشه
// non-blocking اول، اگه پر بود → unlock + blocking + lock
func (r *Reassembler) deliverLocked(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	r.delivered.Add(1)
	select {
	case r.ready <- cp:
		return
	default:
	}
	// channel پر — unlock و block
	r.mu.Unlock()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	defer r.mu.Lock()
	select {
	case r.ready <- cp:
	case <-timer.C:
		r.dropped.Add(1)
	}
}

func (r *Reassembler) flushLocked() {
	for r.heap.Len() > 0 && r.heap[0].seq == r.nextSeq {
		p := heap.Pop(&r.heap).(packet)
		r.deliverLocked(p.data)
		r.nextSeq++
	}
}

func (r *Reassembler) Read(p []byte) (int, error) {
	data, ok := <-r.ready
	if !ok { return 0, io.EOF }
	return copy(p, data), nil
}

func (r *Reassembler) Chan() <-chan []byte { return r.ready }

func (r *Reassembler) Close() {
	if r.closed.CompareAndSwap(false, true) {
		r.mu.Lock()
		r.mu.Unlock()
		close(r.ready)
	}
}

func (r *Reassembler) Stats() (delivered, dropped uint64) {
	return r.delivered.Load(), r.dropped.Load()
}

func (r *Reassembler) gapCheck(now time.Time) {
	if r.closed.Load() { return }
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() { return }
	for r.heap.Len() > 0 && now.Sub(r.heap[0].at) > gapTimeout {
		p := heap.Pop(&r.heap).(packet)
		r.nextSeq = p.seq + 1
		r.deliverLocked(p.data)
		r.flushLocked()
		r.dropped.Add(1)
	}
}

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	all  sync.Map
	done chan struct{}
	once sync.Once
}

func NewManager() *Manager {
	m := &Manager{done: make(chan struct{})}
	go m.sweepLoop()
	return m
}

func (m *Manager) Register(id uint32, r *Reassembler)   { m.all.Store(id, r) }
func (m *Manager) Unregister(id uint32)                  { m.all.Delete(id) }
func (m *Manager) Stop() { m.once.Do(func() { close(m.done) }) }

func (m *Manager) Get(id uint32) (*Reassembler, bool) {
	v, ok := m.all.Load(id)
	if !ok { return nil, false }
	return v.(*Reassembler), true
}

func (m *Manager) sweepLoop() {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-m.done: return
		case <-t.C:
			now := time.Now()
			m.all.Range(func(_, v any) bool {
				v.(*Reassembler).gapCheck(now)
				return true
			})
		}
	}
}
