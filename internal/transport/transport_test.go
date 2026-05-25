package transport_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Qteam-official/QS-Tunnel/internal/transport"
)

func TestUDPSendRecv(t *testing.T) {
	// sender
	sender, err := transport.NewUDP(0) // port 0 = random
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// receiver
	receiver, err := transport.NewUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	dstAddr := receiver.LocalAddr()
	data := []byte("hello world")

	// ارسال
	if err := sender.Send(dstAddr, data); err != nil {
		t.Fatalf("send: %v", err)
	}

	// دریافت
	buf := make([]byte, 1500)
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := receiver.Recv(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Errorf("data mismatch: got %q want %q", buf[:n], data)
	}
	if from == nil {
		t.Error("from address is nil")
	}
}

func TestUDPLargePacket(t *testing.T) {
	sender, _ := transport.NewUDP(0)
	receiver, _ := transport.NewUDP(0)
	defer sender.Close()
	defer receiver.Close()

	data := bytes.Repeat([]byte("x"), 1400)
	sender.Send(receiver.LocalAddr(), data)

	buf := make([]byte, 2000)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := receiver.Recv(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1400 {
		t.Errorf("size: got %d want 1400", n)
	}
}

func TestUDPMultipleMessages(t *testing.T) {
	sender, _ := transport.NewUDP(0)
	receiver, _ := transport.NewUDP(0)
	defer sender.Close()
	defer receiver.Close()

	const N = 100
	for i := 0; i < N; i++ {
		msg := []byte{byte(i)}
		if err := sender.Send(receiver.LocalAddr(), msg); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	buf := make([]byte, 1500)
	received := 0
	for received < N {
		receiver.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := receiver.Recv(buf)
		if err != nil {
			break
		}
		if n == 1 {
			received++
		}
	}
	if received < N*9/10 { // حداقل 90٪
		t.Errorf("received %d/%d packets", received, N)
	}
}

func TestUDPTimeout(t *testing.T) {
	r, _ := transport.NewUDP(0)
	defer r.Close()

	buf := make([]byte, 1500)
	r.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _, err := r.Recv(buf)
	if err == nil {
		t.Error("expected timeout error")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Errorf("expected timeout, got: %v", err)
	}
}

func TestUDPClose(t *testing.T) {
	r, _ := transport.NewUDP(0)
	r.Close()

	buf := make([]byte, 1500)
	r.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err := r.Recv(buf)
	if err == nil {
		t.Error("expected error after close")
	}
}

func BenchmarkUDPSend(b *testing.B) {
	sender, _ := transport.NewUDP(0)
	receiver, _ := transport.NewUDP(0)
	defer sender.Close()

	// drain
	go func() {
		buf := make([]byte, 2000)
		for {
			receiver.Recv(buf)
		}
	}()

	data := make([]byte, 1400)
	dst := receiver.LocalAddr()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.Send(dst, data)
	}
	b.SetBytes(1400)
}
