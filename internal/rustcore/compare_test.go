package rustcore_test

import (
	"testing"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
	"github.com/Qteam-official/QS-Tunnel/internal/reasm"
	"github.com/Qteam-official/QS-Tunnel/internal/rustcore"
)

// ─── EncodeUDP ────────────────────────────────────────────────────────────────

func BenchmarkEncodeUDP_Go(b *testing.B) {
	buf := make([]byte, proto.UDPHdrSize+1400)
	data := make([]byte, 1400)
	b.SetBytes(proto.UDPHdrSize + 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.EncodeUDP(buf, 0x010203, uint32(i), 0, data)
	}
}

func BenchmarkEncodeUDP_Rust(b *testing.B) {
	buf := make([]byte, rustcore.UDPHdrSize+1400)
	data := make([]byte, 1400)
	b.SetBytes(rustcore.UDPHdrSize + 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rustcore.EncodeUDP(buf, 0x010203, uint32(i), 0, data)
	}
}

// ─── DecodeUDP ────────────────────────────────────────────────────────────────

func BenchmarkDecodeUDP_Go(b *testing.B) {
	buf := make([]byte, proto.UDPHdrSize+1400)
	proto.EncodeUDP(buf, 0x010203, 42, 0, make([]byte, 1400))
	b.SetBytes(proto.UDPHdrSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.DecodeUDPHdr(buf)
	}
}

func BenchmarkDecodeUDP_Rust(b *testing.B) {
	buf := make([]byte, rustcore.UDPHdrSize+1400)
	rustcore.EncodeUDP(buf, 0x010203, 42, 0, make([]byte, 1400))
	b.SetBytes(rustcore.UDPHdrSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rustcore.DecodeUDP(buf)
	}
}

// ─── DecodeTCPHdr ─────────────────────────────────────────────────────────────

func BenchmarkDecodeTCPHdr_Go(b *testing.B) {
	buf := make([]byte, proto.TCPHdrSize)
	proto.EncodeTCPHdr(buf, 0xABCDEF, proto.MsgData, 1400)
	b.SetBytes(proto.TCPHdrSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.DecodeTCPHdr(buf)
	}
}

func BenchmarkDecodeTCPHdr_Rust(b *testing.B) {
	buf := make([]byte, rustcore.TCPHdrSize)
	rustcore.EncodeTCPHdr(buf, 0xABCDEF, 0x05, 1400)
	b.SetBytes(rustcore.TCPHdrSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rustcore.DecodeTCPHdr(buf)
	}
}

// ─── ReasmPush in-order ───────────────────────────────────────────────────────

func BenchmarkReasmInOrder_Go(b *testing.B) {
	r := reasm.New(0)
	defer r.Close()
	data := make([]byte, 100)
	go func() {
		for {
			select {
			case <-r.Chan():
			}
		}
	}()
	b.SetBytes(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Push(uint32(i), 0, data)
	}
}

func BenchmarkReasmInOrder_Rust(b *testing.B) {
	r := rustcore.NewReasm(0)
	defer r.Free()
	buf := make([]byte, 100)
	data := make([]byte, 100)
	b.SetBytes(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Push(uint32(i), 0, data)
		for r.Pending() > 0 {
			r.Pop(buf)
		}
	}
}

// ─── ReasmPush out-of-order ───────────────────────────────────────────────────

func BenchmarkReasmOutOfOrder_Go(b *testing.B) {
	r := reasm.New(0)
	defer r.Close()
	data := make([]byte, 100)
	// drain goroutine
	go func() {
		for {
			select {
			case <-r.Chan():
			}
		}
	}()
	b.SetBytes(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint32((i*7 + 3) % 1000)
		r.Push(seq, 0, data)
	}
}

func BenchmarkReasmOutOfOrder_Rust(b *testing.B) {
	r := rustcore.NewReasm(0)
	defer r.Free()
	buf := make([]byte, 100)
	data := make([]byte, 100)
	b.SetBytes(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint32((i*7 + 3) % 1000)
		r.Push(seq, 0, data)
		for r.Pending() > 0 {
			r.Pop(buf)
		}
	}
}

// ─── Crypto Seal 1400 bytes ───────────────────────────────────────────────────

func BenchmarkCryptoSeal_Rust(b *testing.B) {
	key := make([]byte, 32)
	ctx, _ := rustcore.NewCrypto(key)
	defer ctx.Free()
	nonce := make([]byte, 12)
	plain := make([]byte, 1400)
	out := make([]byte, 1400+rustcore.TagSize)
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Seal(nonce, nil, plain, out)
	}
}
