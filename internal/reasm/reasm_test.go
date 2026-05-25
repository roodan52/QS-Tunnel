package reasm_test

import (
	"testing"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
	"github.com/Qteam-official/QS-Tunnel/internal/reasm"
)

func TestInOrder(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()
	for i := uint32(1); i <= 5; i++ {
		r.Push(i, 0, []byte{byte(i)})
	}
	for i := byte(1); i <= 5; i++ {
		select {
		case data := <-r.Chan():
			if data[0] != i {
				t.Errorf("got %d want %d", data[0], i)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timeout seq %d", i)
		}
	}
}

func TestOutOfOrder(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()
	r.Push(3, 0, []byte{3})
	r.Push(1, 0, []byte{1})
	r.Push(2, 0, []byte{2})
	for i := byte(1); i <= 3; i++ {
		select {
		case data := <-r.Chan():
			if data[0] != i {
				t.Errorf("out-of-order: got %d want %d", data[0], i)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timeout seq %d", i)
		}
	}
}

func TestDuplicate(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()
	r.Push(1, 0, []byte{1})
	r.Push(1, 0, []byte{1}) // duplicate — باید نادیده گرفته بشه
	select {
	case <-r.Chan():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout")
	}
	// دومی نباید بیاد
	select {
	case d := <-r.Chan():
		t.Errorf("unexpected duplicate: %v", d)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestGapThenFill(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()
	r.Push(1, 0, []byte{1})
	r.Push(3, 0, []byte{3})
	// فقط ۱ باید بیاد
	select {
	case d := <-r.Chan():
		if d[0] != 1 {
			t.Errorf("got %d want 1", d[0])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout seq 1")
	}
	// ۲ رو پر کن → ۲ و ۳ باید بیان
	r.Push(2, 0, []byte{2})
	for _, want := range []byte{2, 3} {
		select {
		case d := <-r.Chan():
			if d[0] != want {
				t.Errorf("got %d want %d", d[0], want)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timeout seq %d", want)
		}
	}
}

func TestFlagLast(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()
	r.Push(1, 0, []byte("part1"))
	r.Push(2, proto.FlagLast, []byte("part2"))
	for _, want := range []string{"part1", "part2"} {
		select {
		case d := <-r.Chan():
			if string(d) != want {
				t.Errorf("got %q want %q", string(d), want)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timeout")
		}
	}
}

func TestClose(t *testing.T) {
	r := reasm.New(1)
	r.Close()
	// channel باید بسته بشه
	select {
	case _, ok := <-r.Chan():
		_ = ok
	case <-time.After(200 * time.Millisecond):
		t.Fatal("channel not closed")
	}
}

func TestManagerRegisterUnregister(t *testing.T) {
	m := reasm.NewManager()
	defer m.Stop()
	r1 := reasm.New(1)
	r2 := reasm.New(2)
	m.Register(10, r1)
	m.Register(20, r2)

	// باید register شده باشن
	m.Unregister(10)
	// unregister باید بدون panic کار کنه
	m.Unregister(10)  // double unregister — نباید panic بده
	m.Unregister(999) // non-existent — نباید panic بده
	r2.Close()
}

func TestConcurrentPush(t *testing.T) {
	r := reasm.New(1)
	defer r.Close()

	const N = 1000
	done := make(chan struct{})
	go func() {
		defer close(done)
		received := 0
		for received < N {
			select {
			case <-r.Chan():
				received++
			case <-time.After(2 * time.Second):
				t.Errorf("timeout: only received %d/%d", received, N)
				return
			}
		}
	}()

	// ارسال از چند goroutine — ولی seq باید monotonic باشه
	for i := uint32(1); i <= N; i++ {
		r.Push(i, 0, []byte{byte(i % 256)})
	}
	<-done
}

func BenchmarkPushInOrder(b *testing.B) {
	r := reasm.New(1)
	defer r.Close()
	data := make([]byte, 1400)
	go func() {
		for range r.Chan() {
		}
	}()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Push(uint32(i+1), 0, data)
	}
	b.SetBytes(1400)
}

func BenchmarkPushOutOfOrder(b *testing.B) {
	r := reasm.New(1)
	defer r.Close()
	data := make([]byte, 1400)
	go func() {
		for range r.Chan() {
		}
	}()
	b.ResetTimer()
	// نصف پشت سرهم، نصف معکوس
	for i := 0; i < b.N; i++ {
		seq := uint32(i + 1)
		if i%2 == 0 {
			r.Push(seq, 0, data)
		} else {
			r.Push(seq-1, 0, data)
		}
	}
	b.SetBytes(1400)
}
