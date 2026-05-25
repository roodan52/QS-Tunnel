package rustcore_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Qteam-official/QS-Tunnel/internal/rustcore"
)

// ─── Proto Tests ──────────────────────────────────────────────────────────────

func TestUDPEncodeDecodeRoundtrip(t *testing.T) {
	cases := []struct {
		sid   uint32
		seq   uint32
		flags byte
		data  []byte
	}{
		{0x010203, 0, 0, []byte("hello")},
		{0xFFFFFF, 1<<24 - 1, 0x01, make([]byte, 1400)},
		{0x000001, 100, 0, []byte{}},
		{0xABCDEF, 999, 0, bytes.Repeat([]byte{0xDE}, 500)},
	}

	rand.Read(cases[1].data)

	for i, c := range cases {
		buf := make([]byte, rustcore.UDPHdrSize+len(c.data))
		n := rustcore.EncodeUDP(buf, c.sid, c.seq, c.flags, c.data)
		if n != rustcore.UDPHdrSize+len(c.data) {
			t.Fatalf("case %d: encode returned %d want %d", i, n, rustcore.UDPHdrSize+len(c.data))
		}

		sid, seq, flags, ps, err := rustcore.DecodeUDP(buf)
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if sid != c.sid {
			t.Fatalf("case %d: sid %x != %x", i, sid, c.sid)
		}
		if seq != c.seq {
			t.Fatalf("case %d: seq %d != %d", i, seq, c.seq)
		}
		if flags != c.flags {
			t.Fatalf("case %d: flags %x != %x", i, flags, c.flags)
		}
		if ps != rustcore.UDPHdrSize {
			t.Fatalf("case %d: payload start %d", i, ps)
		}
		if !bytes.Equal(buf[ps:], c.data) {
			t.Fatalf("case %d: payload mismatch", i)
		}
	}
}

func TestUDPDecodeInvalidMagic(t *testing.T) {
	buf := make([]byte, rustcore.UDPHdrSize)
	buf[7] = 0x00 // magic غلط
	buf[8] = 0x00
	_, _, _, _, err := rustcore.DecodeUDP(buf)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestUDPDecodeTooShort(t *testing.T) {
	buf := make([]byte, 4)
	_, _, _, _, err := rustcore.DecodeUDP(buf)
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestTCPHdrRoundtrip(t *testing.T) {
	cases := []struct {
		sid     uint32
		msgType byte
		payLen  int
	}{
		{0x010203, 0x05, 100},
		{0xFFFFFF, 0x01, 65535},
		{0x000000, 0x05, 0},
		{0xABCDEF, 0x02, 1400},
	}

	for _, c := range cases {
		buf := make([]byte, rustcore.TCPHdrSize)
		if !rustcore.EncodeTCPHdr(buf, c.sid, c.msgType, c.payLen) {
			t.Fatalf("encode failed for %+v", c)
		}
		sid, mt, pl, err := rustcore.DecodeTCPHdr(buf)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if sid != c.sid {
			t.Fatalf("sid %x != %x", sid, c.sid)
		}
		if mt != c.msgType {
			t.Fatalf("msgType %x != %x", mt, c.msgType)
		}
		if pl != c.payLen {
			t.Fatalf("payLen %d != %d", pl, c.payLen)
		}
	}
}

func TestTCPHdrTooShort(t *testing.T) {
	buf := make([]byte, 3)
	_, _, _, err := rustcore.DecodeTCPHdr(buf)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ─── Reasm Tests ──────────────────────────────────────────────────────────────

func TestReasmInOrder(t *testing.T) {
	r := rustcore.NewReasm(0)
	defer r.Free()

	buf := make([]byte, 1500)
	for i := 0; i < 100; i++ {
		r.Push(uint32(i), 0, []byte{byte(i)})
	}
	for i := 0; i < 100; i++ {
		n := r.Pop(buf)
		if n != 1 {
			t.Fatalf("seq %d: pop returned %d", i, n)
		}
		if buf[0] != byte(i) {
			t.Fatalf("seq %d: got %d want %d", i, buf[0], i)
		}
	}
}

func TestReasmOutOfOrder(t *testing.T) {
	r := rustcore.NewReasm(0)
	defer r.Free()

	// ارسال معکوس — seq 9,8,...,1,0
	// وقتی seq=0 ارسال میشه، همه flush میشن
	for i := 9; i >= 0; i-- {
		r.Push(uint32(i), 0, []byte{byte(i)})
	}
	// الان همه باید در ready queue باشن
	buf := make([]byte, 1500)
	for i := 0; i < 10; i++ {
		n := r.Pop(buf)
		if n != 1 {
			t.Fatalf("seq %d: pop returned %d (pending=%d)", i, n, r.Pending())
		}
		if buf[0] != byte(i) {
			t.Fatalf("got %d want %d", buf[0], i)
		}
	}
}

func TestReasmDuplicate(t *testing.T) {
	r := rustcore.NewReasm(0)
	defer r.Free()
	buf := make([]byte, 1500)

	r.Push(0, 0, []byte{1})
	r.Push(0, 0, []byte{2}) // duplicate — باید drop بشه
	r.Push(1, 0, []byte{3})

	// فقط دو تا باید بیاد
	n1 := r.Pop(buf)
	if n1 != 1 || buf[0] != 1 {
		t.Fatalf("pkt0: n=%d v=%d", n1, buf[0])
	}
	n2 := r.Pop(buf)
	if n2 != 1 || buf[0] != 3 {
		t.Fatalf("pkt1: n=%d v=%d", n2, buf[0])
	}
	n3 := r.Pop(buf)
	if n3 != 0 {
		t.Fatalf("expected empty, got %d", n3)
	}

	// seq=0 duplicate باید drop بشه
	// ولی چون seq < next_seq هست، dropped ممکنه count نشه
	// مهم‌تر اینه که فقط دو تا پکت تحویل داده شد
	d, _ := r.Stats()
	if d != 2 {
		t.Fatalf("expected 2 delivered, got %d", d)
	}
}

func TestReasmGapFill(t *testing.T) {
	r := rustcore.NewReasm(0)
	defer r.Free()
	buf := make([]byte, 1500)

	r.Push(0, 0, []byte{0})
	r.Push(2, 0, []byte{2}) // gap at seq=1
	r.Push(1, 0, []byte{1}) // fill gap

	for i := byte(0); i < 3; i++ {
		n := r.Pop(buf)
		if n != 1 {
			t.Fatalf("seq %d: n=%d", i, n)
		}
		if buf[0] != i {
			t.Fatalf("seq %d: got %d", i, buf[0])
		}
	}
}

func TestReasmCloseAndFree(t *testing.T) {
	r := rustcore.NewReasm(0)
	r.Push(0, 0, []byte{1})
	r.Close()
	r.Push(1, 0, []byte{2}) // بعد از close — نباید panic بده
	r.Free()
	// نباید crash بده
}

func TestReasmStats(t *testing.T) {
	r := rustcore.NewReasm(0)
	defer r.Free()

	for i := 0; i < 10; i++ {
		r.Push(uint32(i), 0, []byte{byte(i)})
	}
	buf := make([]byte, 100)
	for r.Pending() > 0 {
		r.Pop(buf)
	}

	delivered, _ := r.Stats()
	if delivered != 10 {
		t.Fatalf("delivered=%d want 10", delivered)
	}
}

func TestReasmLargeOutOfOrder(t *testing.T) {
	// تست با N پکت در ترتیب معکوس
	r := rustcore.NewReasm(0)
	defer r.Free()

	const N = 100 // باید کمتر از MAX_BUFFERED (512) باشه
	// ارسال معکوس — آخرین پکت (seq=0) همه رو unlock میکنه
	for i := N - 1; i >= 0; i-- {
		r.Push(uint32(i), 0, []byte{byte(i % 256)})
	}

	buf := make([]byte, 100)
	for i := 0; i < N; i++ {
		n := r.Pop(buf)
		if n != 1 {
			t.Fatalf("seq %d: pop=%d (pending=%d)", i, n, r.Pending())
		}
		if buf[0] != byte(i%256) {
			t.Fatalf("seq %d: got %d want %d", i, buf[0], i%256)
		}
	}

	d, _ := r.Stats()
	if d != N {
		t.Fatalf("delivered=%d want %d", d, N)
	}
}

// ─── Crypto Tests ─────────────────────────────────────────────────────────────

func TestCryptoSealOpen(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	ctx, err := rustcore.NewCrypto(key)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	nonce := make([]byte, 12)
	rand.Read(nonce)
	plain := []byte("hello from rust crypto")
	aad := []byte("additional data")
	out := make([]byte, len(plain)+rustcore.TagSize)

	n, err := ctx.Seal(nonce, aad, plain, out)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if n != len(plain)+rustcore.TagSize {
		t.Fatalf("seal len %d", n)
	}

	decrypted := make([]byte, len(plain))
	m, err := ctx.Open(nonce, aad, out[:n], decrypted)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if m != len(plain) {
		t.Fatalf("open len %d", m)
	}
	if !bytes.Equal(decrypted[:m], plain) {
		t.Fatal("plaintext mismatch")
	}
}

func TestCryptoAuthFailure(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx, _ := rustcore.NewCrypto(key)
	defer ctx.Free()

	nonce := make([]byte, 12)
	plain := []byte("test data")
	out := make([]byte, len(plain)+rustcore.TagSize)
	n, _ := ctx.Seal(nonce, nil, plain, out)

	// تغییر یه بایت — باید auth fail بشه
	out[0] ^= 0xFF
	decrypted := make([]byte, len(plain))
	_, err := ctx.Open(nonce, nil, out[:n], decrypted)
	if err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestCryptoWrongKeySize(t *testing.T) {
	_, err := rustcore.NewCrypto([]byte("short"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestCryptoLargePayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ctx, _ := rustcore.NewCrypto(key)
	defer ctx.Free()

	nonce := make([]byte, 12)
	rand.Read(nonce)
	plain := make([]byte, 64*1024) // 64KB
	rand.Read(plain)

	out := make([]byte, len(plain)+rustcore.TagSize)
	n, err := ctx.Seal(nonce, nil, plain, out)
	if err != nil {
		t.Fatal(err)
	}

	dec := make([]byte, len(plain))
	m, err := ctx.Open(nonce, nil, out[:n], dec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec[:m], plain) {
		t.Fatal("large payload mismatch")
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────
