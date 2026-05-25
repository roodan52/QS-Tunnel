package tests_test

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
	"github.com/Qteam-official/QS-Tunnel/internal/reasm"
	"github.com/Qteam-official/QS-Tunnel/internal/sendpool"
	"github.com/Qteam-official/QS-Tunnel/internal/transport"
)

// ─── 1. Reasm: 500 concurrent streams, reverse order ─────────────────────────

func TestStress500Streams(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()

	const streams, pkts = 500, 50
	var delivered, timeouts atomic.Int64
	var wg sync.WaitGroup

	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func(sid uint32) {
			defer wg.Done()
			r := reasm.New(0)
			mgr.Register(sid, r)
			defer func() { mgr.Unregister(sid); r.Close() }()

			for i := pkts - 1; i >= 0; i-- {
				r.Push(uint32(i), 0, []byte{byte(i)})
			}
			for i := 0; i < pkts; i++ {
				select {
				case d, ok := <-r.Chan():
					if !ok {
						return
					}
					if d[0] != byte(i) {
						t.Errorf("stream %d seq %d: got %d", sid, i, d[0])
					}
					delivered.Add(1)
				case <-time.After(3 * time.Second):
					timeouts.Add(1)
					return
				}
			}
		}(uint32(s))
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		t.Logf("✅ delivered=%d timeouts=%d", delivered.Load(), timeouts.Load())
		if timeouts.Load() > 0 {
			t.Errorf("❌ %d timeouts", timeouts.Load())
		}
		if delivered.Load() != streams*pkts {
			t.Errorf("❌ delivered=%d want=%d", delivered.Load(), streams*pkts)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("DEADLOCK")
	}
}

// ─── 2. Manager: no deadlock ─────────────────────────────────────────────────

func TestManagerNoDeadlock(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()

	var ops atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				id := uint32(gid*500 + i)
				r := reasm.New(0)
				mgr.Register(id, r)
				r.Push(0, 0, []byte{1})
				select {
				case <-r.Chan():
				default:
				}
				mgr.Unregister(id)
				r.Close()
				ops.Add(1)
			}
		}(g)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		t.Logf("✅ %d ops no deadlock", ops.Load())
	case <-time.After(20 * time.Second):
		t.Fatalf("DEADLOCK — %d ops", ops.Load())
	}
}

// ─── 3. Sendpool: 100K pkts, zero drop ──────────────────────────────────────

func TestSendpoolZeroDrop(t *testing.T) {
	srv, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer srv.Close()
	tr, err := transport.NewUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	pool, _ := sendpool.New(sendpool.Config{Workers: 8, QueueSize: 32768, Transport: tr})
	defer pool.Close()

	dst := srv.LocalAddr().(*net.UDPAddr)
	data := make([]byte, 1400)
	const total = 100_000
	var wg sync.WaitGroup

	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < total/100; i++ {
				pool.Send(sendpool.Packet{
					StreamID: uint32(gid*1000 + i),
					Data:     data,
					Dst:      dst,
				})
			}
		}(g)
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	sent, dropped := pool.Stats()
	t.Logf("✅ sent=%d dropped=%d (%.3f%%)", sent, dropped,
		float64(dropped)/float64(sent+dropped)*100)
	if dropped > 0 {
		t.Errorf("❌ %d drops — باید صفر باشه", dropped)
	}
}

// ─── 4. Proto edge cases ─────────────────────────────────────────────────────

func TestProtoEdgeCases(t *testing.T) {
	buf := make([]byte, proto.UDPHdrSize)
	proto.EncodeUDP(buf, 0xFFFFFF, 1<<24-1, proto.FlagLast, nil)
	h, _, err := proto.DecodeUDPHdr(buf)
	if err != nil {
		t.Fatal(err)
	}
	if h.StreamID != 0xFFFFFF {
		t.Fatal("sid")
	}
	if h.Seq != 1<<24-1 {
		t.Fatal("seq")
	}
	if h.Flags != proto.FlagLast {
		t.Fatal("flags")
	}

	hdr := make([]byte, proto.TCPHdrSize)
	proto.EncodeTCPHdr(hdr, 0xFFFFFF, proto.MsgData, 65535)
	sid, mt, plen := proto.DecodeTCPHdr(hdr)
	if sid != 0xFFFFFF || mt != proto.MsgData || plen != 65535 {
		t.Fatal("tcp hdr")
	}
}

// ─── 5. Race condition: concurrent push/pop ──────────────────────────────────

func TestRaceCondition(t *testing.T) {
	r := reasm.New(0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Push(uint32(base*100+i), 0, []byte{byte(i)})
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case _, ok := <-r.Chan():
				if !ok {
					return
				}
			case <-deadline:
				r.Close()
				return
			}
		}
	}()
	wg.Wait()
}

// ─── 6. Memory: هزاران reassembler ساخت و destroy ─────────────────────────────

func TestMemoryNoLeak5000(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()
	for i := 0; i < 5000; i++ {
		id := uint32(i)
		r := reasm.New(0)
		mgr.Register(id, r)
		r.Push(0, 0, []byte{1})
		select {
		case <-r.Chan():
		default:
		}
		mgr.Unregister(id)
		r.Close()
	}
	t.Log("✅ 5000 streams created/destroyed")
}

// ─── 7. Backpressure: fast producer + slow consumer ──────────────────────────

func TestBackpressure(t *testing.T) {
	r := reasm.New(0)
	defer r.Close()
	var consumed atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case _, ok := <-r.Chan():
				if !ok {
					return
				}
				consumed.Add(1)
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	for i := uint32(0); i < 5000; i++ {
		r.Push(i, 0, []byte{byte(i % 256)})
	}
	time.Sleep(500 * time.Millisecond)
	r.Close()
	<-done
	d, dr := r.Stats()
	t.Logf("✅ delivered=%d dropped=%d consumed=%d", d, dr, consumed.Load())
	if d < 2500 {
		t.Errorf("❌ too few delivered: %d", d)
	}
}
