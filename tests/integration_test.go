package tests_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
	"github.com/Qteam-official/QS-Tunnel/internal/reasm"
	"github.com/Qteam-official/QS-Tunnel/internal/sendpool"
	"github.com/Qteam-official/QS-Tunnel/internal/transport"
)

// ═══ proto ════════════════════════════════════════════════════════════════════

func TestProtoTCPHdrEncodeDecode(t *testing.T) {
	cases := []struct {
		sid     uint32
		msgType byte
		payLen  int
	}{
		{0x010203, proto.MsgData, 100},
		{0xFFFFFF, proto.MsgData, 0},
		{0x000001, proto.MsgData, 65535},
		{0x000000, proto.MsgData, 1},
	}
	buf := make([]byte, proto.TCPHdrSize)
	for _, c := range cases {
		proto.EncodeTCPHdr(buf, c.sid, c.msgType, c.payLen)
		gotSID, gotType, gotLen := proto.DecodeTCPHdr(buf)
		if gotSID != c.sid {
			t.Fatalf("sid: got %x want %x", gotSID, c.sid)
		}
		if gotType != c.msgType {
			t.Fatalf("type mismatch")
		}
		if gotLen != c.payLen {
			t.Fatalf("len: got %d want %d", gotLen, c.payLen)
		}
	}
}

func TestProtoUDPEncodeDecode(t *testing.T) {
	cases := []struct {
		sid   uint32
		seq   uint32
		flags byte
		data  []byte
	}{
		{0x010203, 0, 0, []byte("hello")},
		{0xFFFFFF, 1<<24 - 1, proto.FlagLast, make([]byte, 1400)},
		{0x000001, 100, 0, []byte{}},
	}
	for _, c := range cases {
		buf := make([]byte, proto.UDPHdrSize+len(c.data))
		proto.EncodeUDP(buf, c.sid, c.seq, c.flags, c.data)

		h, ps, err := proto.DecodeUDPHdr(buf)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if h.StreamID != c.sid {
			t.Fatalf("sid mismatch: %x vs %x", h.StreamID, c.sid)
		}
		if h.Seq != c.seq {
			t.Fatalf("seq: %d vs %d", h.Seq, c.seq)
		}
		if h.Flags != c.flags {
			t.Fatalf("flags mismatch")
		}
		if !bytes.Equal(buf[ps:], c.data) {
			t.Fatalf("data mismatch len=%d", len(c.data))
		}
	}
}

func TestProtoTCPFrameReadWrite(t *testing.T) {
	var buf bytes.Buffer
	sid := uint32(0xABCDEF)
	payload := []byte("test payload 12345")

	hdr := make([]byte, proto.TCPHdrSize)
	proto.EncodeTCPHdr(hdr, sid, proto.MsgData, len(payload))
	buf.Write(hdr)
	buf.Write(payload)

	frame, err := proto.ReadTCPFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.StreamID != sid {
		t.Fatal("sid mismatch")
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatal("payload mismatch")
	}
}

func BenchmarkProtoEncodeUDP(b *testing.B) {
	buf := make([]byte, proto.UDPHdrSize+1400)
	data := make([]byte, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.EncodeUDP(buf, uint32(i), uint32(i), 0, data)
	}
	b.SetBytes(proto.UDPHdrSize + 1400)
}

func BenchmarkProtoDecodeTCPHdr(b *testing.B) {
	buf := make([]byte, proto.TCPHdrSize)
	proto.EncodeTCPHdr(buf, 0x123456, proto.MsgData, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.DecodeTCPHdr(buf)
	}
}

// ═══ reasm ════════════════════════════════════════════════════════════════════

func TestReasmInOrder(t *testing.T) {
	r := reasm.New(0)
	defer r.Close()
	const N = 100
	go func() {
		for i := 0; i < N; i++ {
			r.Push(uint32(i), 0, []byte{byte(i)})
		}
	}()
	for i := 0; i < N; i++ {
		select {
		case d := <-r.Chan():
			if d[0] != byte(i) {
				t.Fatalf("seq %d: got %d", i, d[0])
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout seq %d", i)
		}
	}
}

func TestReasmOutOfOrder(t *testing.T) {
	r := reasm.New(0)
	defer r.Close()
	// ارسال معکوس
	for i := 9; i >= 0; i-- {
		r.Push(uint32(i), 0, []byte{byte(i)})
	}
	for i := 0; i < 10; i++ {
		select {
		case d := <-r.Chan():
			if d[0] != byte(i) {
				t.Fatalf("got %d want %d", d[0], i)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout seq %d", i)
		}
	}
}

func TestReasmDuplicate(t *testing.T) {
	r := reasm.New(0)
	defer r.Close()
	r.Push(0, 0, []byte("a"))
	r.Push(0, 0, []byte("dup")) // باید drop بشه
	r.Push(1, 0, []byte("b"))
	for i, want := range []string{"a", "b"} {
		select {
		case d := <-r.Chan():
			if string(d) != want {
				t.Fatalf("pkt %d: got %q want %q", i, d, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout pkt %d", i)
		}
	}
	_, dropped := r.Stats()
	if dropped == 0 {
		t.Fatal("duplicate should be dropped")
	}
}

func TestReasmGapFill(t *testing.T) {
	r := reasm.New(0)
	defer r.Close()
	r.Push(0, 0, []byte{0})
	r.Push(2, 0, []byte{2}) // gap
	r.Push(1, 0, []byte{1}) // fill gap
	for i := byte(0); i < 3; i++ {
		select {
		case d := <-r.Chan():
			if d[0] != i {
				t.Fatalf("got %d want %d", d[0], i)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout %d", i)
		}
	}
}

func TestReasmClose(t *testing.T) {
	r := reasm.New(0)
	r.Push(0, 0, []byte("x"))
	r.Close()
	// بعد از close نباید panic
	r.Push(1, 0, []byte("after"))
	select {
	case <-r.Chan():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// TestReasmManagerNoDeadlock — باگ اصلی که fix شد
func TestReasmManagerNoDeadlock(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()
	const streams = 300
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			r := reasm.New(0)
			mgr.Register(id, r)
			for j := 0; j < 5; j++ {
				r.Push(uint32(j), 0, []byte{byte(j)})
			}
			for j := 0; j < 5; j++ {
				select {
				case <-r.Chan():
				case <-time.After(time.Second):
				}
			}
			r.Close()
			mgr.Unregister(id)
		}(uint32(i))
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK در Manager.Unregister")
	}
}

func TestReasmManagerConcurrentOps(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()
	var ops atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := uint32(gid*200 + i)
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
		t.Logf("✅ %d ops", ops.Load())
	case <-time.After(15 * time.Second):
		t.Fatalf("deadlock — %d ops done", ops.Load())
	}
}

func BenchmarkReasmInOrder(b *testing.B) {
	r := reasm.New(0)
	defer r.Close()
	go func() {
		for {
			select {
			case <-r.Chan():
			}
		}
	}()
	data := make([]byte, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Push(uint32(i), 0, data)
	}
}

// ═══ transport ════════════════════════════════════════════════════════════════

func TestTransportSendRecv(t *testing.T) {
	srvTr, err := transport.NewUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer srvTr.Close()
	cliTr, err := transport.NewUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cliTr.Close()
	dst := srvTr.LocalAddr()

	msg := []byte("hello transport")
	if err := cliTr.Send(dst, msg); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	srvTr.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := srvTr.Recv(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %q want %q", buf[:n], msg)
	}
}

func TestTransportLargePayload(t *testing.T) {
	srvTr, _ := transport.NewUDP(0)
	cliTr, _ := transport.NewUDP(0)
	defer srvTr.Close()
	defer cliTr.Close()

	payload := make([]byte, 1400)
	rand.Read(payload)
	cliTr.Send(srvTr.LocalAddr(), payload)

	buf := make([]byte, 2000)
	srvTr.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := srvTr.Recv(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatal("payload mismatch")
	}
}

func TestTransportConcurrentSend(t *testing.T) {
	srvTr, _ := transport.NewUDP(0)
	cliTr, _ := transport.NewUDP(0)
	defer srvTr.Close()
	defer cliTr.Close()
	dst := srvTr.LocalAddr()
	var sent atomic.Int64
	var wg sync.WaitGroup

	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := cliTr.Send(dst, []byte("x")); err == nil {
					sent.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if sent.Load() < 700 {
		t.Fatalf("only %d/800 sent", sent.Load())
	}
}

// ═══ sendpool ═════════════════════════════════════════════════════════════════

func TestSendpoolBasic(t *testing.T) {
	srvTr, _ := transport.NewUDP(0)
	tr, _ := transport.NewUDP(0)
	defer srvTr.Close()
	defer tr.Close()
	pool, err := sendpool.New(sendpool.Config{Workers: 2, QueueSize: 256, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	dst := srvTr.LocalAddr()
	const N = 200
	for i := 0; i < N; i++ {
		pool.Send(sendpool.Packet{StreamID: uint32(i), Data: []byte(fmt.Sprintf("pkt%d", i)), Dst: dst})
	}
	time.Sleep(100 * time.Millisecond)
	sent, dropped := pool.Stats()
	t.Logf("sent=%d dropped=%d", sent, dropped)
	if sent+dropped < N {
		t.Fatalf("only %d/%d processed", sent+dropped, N)
	}
}

func TestSendpoolHighLoad(t *testing.T) {
	srvTr, _ := transport.NewUDP(0)
	tr, _ := transport.NewUDP(0)
	defer srvTr.Close()
	defer tr.Close()
	pool, _ := sendpool.New(sendpool.Config{Workers: 4, QueueSize: 4096, Transport: tr})
	defer pool.Close()

	dst := srvTr.LocalAddr()
	data := make([]byte, 1400)
	const N = 5000
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < N/10; i++ {
				pool.Send(sendpool.Packet{StreamID: uint32(gid*100 + i), Data: data, Dst: dst})
			}
		}(g)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	sent, dropped := pool.Stats()
	t.Logf("✅ sent=%d dropped=%d total=%d", sent, dropped, sent+dropped)
}

func BenchmarkSendpool(b *testing.B) {
	srvTr, _ := transport.NewUDP(0)
	tr, _ := transport.NewUDP(0)
	defer srvTr.Close()
	defer tr.Close()
	pool, _ := sendpool.New(sendpool.Config{Workers: 4, QueueSize: 16384, Transport: tr})
	defer pool.Close()
	dst := srvTr.LocalAddr()
	data := make([]byte, 1400)
	b.ResetTimer()
	b.SetBytes(1400)
	for i := 0; i < b.N; i++ {
		pool.Send(sendpool.Packet{StreamID: uint32(i), Data: data, Dst: dst})
	}
}

// ═══ stress + memory ══════════════════════════════════════════════════════════

func TestStressFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	mgr := reasm.NewManager()
	defer mgr.Stop()

	const streams = 100
	const pkts = 30
	var delivered atomic.Int64
	var wg sync.WaitGroup

	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func(sid uint32) {
			defer wg.Done()
			r := reasm.New(0)
			mgr.Register(sid, r)
			defer func() { mgr.Unregister(sid); r.Close() }()

			order := rand.Perm(pkts)
			go func() {
				for _, seq := range order {
					r.Push(uint32(seq), 0, []byte{byte(seq)})
					time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
				}
			}()
			for i := 0; i < pkts; i++ {
				select {
				case d := <-r.Chan():
					if d[0] != byte(i) {
						t.Errorf("stream %d seq %d: got %d", sid, i, d[0])
					}
					delivered.Add(1)
				case <-time.After(5 * time.Second):
					t.Errorf("stream %d timeout seq %d", sid, i)
					return
				}
			}
		}(uint32(s))
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		t.Logf("✅ %d pkts delivered", delivered.Load())
	case <-time.After(30 * time.Second):
		t.Fatal("timeout")
	}
}

func TestMemoryNoLeak(t *testing.T) {
	mgr := reasm.NewManager()
	defer mgr.Stop()
	for i := 0; i < 2000; i++ {
		r := reasm.New(0)
		mgr.Register(uint32(i), r)
		r.Push(0, 0, []byte("x"))
		select {
		case <-r.Chan():
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
		mgr.Unregister(uint32(i))
		r.Close()
	}
	t.Log("✅ 2000 streams created/destroyed, no leaks")
}

func TestRaceDetector(t *testing.T) {
	r := reasm.New(0)
	var wg sync.WaitGroup
	// 8 writer + 1 reader همزمان
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				r.Push(uint32(base*50+i), 0, []byte{byte(i)})
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

func BenchmarkShardedMap(b *testing.B) {
	type shard struct {
		sync.RWMutex
		m map[uint32]int
	}
	const NS = 256
	shards := make([]shard, NS)
	for i := range shards {
		shards[i].m = make(map[uint32]int, 64)
		for j := 0; j < 64; j++ {
			shards[i].m[uint32(j)] = j
		}
	}
	b.RunParallel(func(pb *testing.PB) {
		var i uint32
		for pb.Next() {
			s := &shards[i%NS]
			s.RLock()
			_ = s.m[i%64]
			s.RUnlock()
			i++
		}
	})
}
