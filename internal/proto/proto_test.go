package proto_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/Qteam-official/QS-Tunnel/internal/proto"
)

func TestTCPHdrRoundTrip(t *testing.T) {
	cases := []struct {
		sid  uint32
		mt   byte
		plen int
	}{
		{0, proto.MsgHello, 0},
		{1, proto.MsgData, 100},
		{0xFFFFFF, proto.MsgConnect, 1400},
		{42, proto.MsgClose, 0},
		{999, proto.MsgPing, 0},
	}
	hdr := make([]byte, proto.TCPHdrSize)
	for _, c := range cases {
		proto.EncodeTCPHdr(hdr, c.sid, c.mt, c.plen)
		sid, mt, plen := proto.DecodeTCPHdr(hdr)
		if sid != c.sid {
			t.Errorf("sid: got %d want %d", sid, c.sid)
		}
		if mt != c.mt {
			t.Errorf("mt: got %d want %d", mt, c.mt)
		}
		if plen != c.plen {
			t.Errorf("plen: got %d want %d", plen, c.plen)
		}
	}
}

func TestUDPRoundTrip(t *testing.T) {
	cases := []struct {
		sid, seq uint32
		flags    byte
		data     string
	}{
		{1, 1, 0, "hello"},
		{0xFFFFFF, 0xFFFFFF, proto.FlagLast, "end"},
		{100, 200, proto.FlagClose, ""},
		{0, 0, 0, string(bytes.Repeat([]byte("z"), 1400))},
	}
	for _, c := range cases {
		payload := []byte(c.data)
		frame := make([]byte, proto.UDPHdrSize+len(payload))
		proto.EncodeUDP(frame, c.sid, c.seq, c.flags, payload)

		if frame[0] != 0xAB || frame[1] != 0xCD {
			t.Errorf("magic wrong: %02x%02x", frame[0], frame[1])
		}
		sid := uint32(frame[2])<<16 | uint32(frame[3])<<8 | uint32(frame[4])
		seq := uint32(frame[5])<<16 | uint32(frame[6])<<8 | uint32(frame[7])
		flags := frame[8]
		if sid != c.sid {
			t.Errorf("sid: got %d want %d", sid, c.sid)
		}
		if seq != c.seq {
			t.Errorf("seq: got %d want %d", seq, c.seq)
		}
		if flags != c.flags {
			t.Errorf("flags: got %d want %d", flags, c.flags)
		}
		if !bytes.Equal(frame[proto.UDPHdrSize:], payload) {
			t.Error("payload mismatch")
		}
	}
}

func TestHelloRoundTrip(t *testing.T) {
	ip4 := net.ParseIP("192.168.1.100").To4()
	port := uint16(8000)
	payload := proto.EncodeHello([proto.SessionIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8}, ip4, port)
	sid, ip, p, err := proto.DecodeHello(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sid[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("sessionID mismatch")
	}
	if !ip.Equal(ip4) {
		t.Errorf("IP: got %v want %v", ip, ip4)
	}
	if p != port {
		t.Errorf("port: got %d want %d", p, port)
	}
}

func TestConnectRoundTrip(t *testing.T) {
	// domain: باید با length prefix باشه
	domainName := "google.com"
	domainAddr := append([]byte{byte(len(domainName))}, []byte(domainName)...)

	cases := []proto.ConnectPayload{
		{AddrType: 3, Addr: domainAddr, Port: 443},
		{AddrType: 1, Addr: net.ParseIP("8.8.8.8").To4(), Port: 80},
		{AddrType: 1, Addr: net.ParseIP("1.1.1.1").To4(), Port: 53},
	}
	for _, c := range cases {
		enc := proto.EncodeConnect(c)
		dec, err := proto.DecodeConnect(enc)
		if err != nil {
			t.Fatalf("decode: %v (addrType=%d)", err, c.AddrType)
		}
		if dec.Port != c.Port {
			t.Errorf("port: got %d want %d", dec.Port, c.Port)
		}
		if dec.AddrType != c.AddrType {
			t.Errorf("addrType: got %d want %d", dec.AddrType, c.AddrType)
		}
	}
}

func BenchmarkEncodeUDP(b *testing.B) {
	frame := make([]byte, proto.UDPHdrSize+1400)
	payload := make([]byte, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proto.EncodeUDP(frame, uint32(i), uint32(i), 0, payload)
	}
	b.SetBytes(1400)
}
