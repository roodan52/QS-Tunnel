package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
)

func main() {
	// benchmark: hot path encode + send
	const N = 1_000_000
	data := make([]byte, 1400)

	// روش قدیم: make در هر iteration
	t1 := time.Now()
	for i := 0; i < N; i++ {
		fsize := proto.UDPHdrSize + len(data)
		frame := make([]byte, fsize)
		proto.EncodeUDP(frame, 1, uint32(i), 0, data)
		_ = frame
	}
	fmt.Printf("make per iter: %v (%.0f ns/op)\n", time.Since(t1), float64(time.Since(t1).Nanoseconds())/N)

	// روش جدید: pool
	pool := sync.Pool{New: func() any {
		b := make([]byte, 2048)
		return &b
	}}
	t2 := time.Now()
	for i := 0; i < N; i++ {
		ptr := pool.Get().(*[]byte)
		buf := (*ptr)[:proto.UDPHdrSize+len(data)]
		proto.EncodeUDP(buf, 1, uint32(i), 0, data)
		// copy برای send
		frame := make([]byte, len(buf))
		copy(frame, buf)
		pool.Put(ptr)
		_ = frame
	}
	fmt.Printf("pool+copy:     %v (%.0f ns/op)\n", time.Since(t2), float64(time.Since(t2).Nanoseconds())/N)

	// روش بهتر: pre-allocated ring buffer
	var counter atomic.Uint64
	ring := make([][]byte, 1024)
	for i := range ring {
		ring[i] = make([]byte, 2048)
	}
	t3 := time.Now()
	for i := 0; i < N; i++ {
		idx := counter.Add(1) % 1024
		buf := ring[idx][:proto.UDPHdrSize+len(data)]
		proto.EncodeUDP(buf, 1, uint32(i), 0, data)
		_ = buf
	}
	fmt.Printf("ring buffer:   %v (%.0f ns/op)\n", time.Since(t3), float64(time.Since(t3).Nanoseconds())/N)
}
