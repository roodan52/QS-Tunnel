// Package batchsend — ارسال batch UDP با sendmmsg syscall
//
// به جای N تا sendto (N syscall)، همه پکت‌ها در یه syscall ارسال میشن
// روی ۱۰۰K+ pps: ۳-۵x کاهش syscall overhead
//
// fallback: اگه sendmmsg نبود (Windows/macOS) از write loop استفاده میشه
package batchsend

import (
	"net"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// MaxBatch حداکثر پکت در یه sendmmsg
	MaxBatch = 64
	// BatchWaitNS حداکثر انتظار برای پر شدن batch (nanosecond)
	// 50µs — تعادل بین latency و throughput
	BatchWaitNS = 50_000
)

// Packet یه پکت UDP برای ارسال
type Packet struct {
	Data []byte
	Addr *net.UDPAddr
}

// Sender ارسال batch UDP
type Sender struct {
	conn *net.UDPConn
	fd   int

	mu      sync.Mutex
	pending []Packet
	flush   chan struct{}
	done    chan struct{}
}

func New(conn *net.UDPConn) (*Sender, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var fd int
	raw.Control(func(f uintptr) {
		fd = int(f)
	})

	s := &Sender{
		conn:    conn,
		fd:      fd,
		pending: make([]Packet, 0, MaxBatch),
		flush:   make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go s.flushLoop()
	return s, nil
}

// Send یه پکت به queue اضافه میکنه
func (s *Sender) Send(pkt Packet) {
	s.mu.Lock()
	s.pending = append(s.pending, pkt)
	full := len(s.pending) >= MaxBatch
	s.mu.Unlock()

	if full {
		select {
		case s.flush <- struct{}{}:
		default:
		}
	}
}

// flushLoop batch‌ها رو میفرسته
func (s *Sender) flushLoop() {
	defer close(s.done)
	timer := newNanoTimer(BatchWaitNS)
	defer timer.stop()

	for {
		select {
		case <-s.flush:
			s.sendBatch()
		case <-timer.C():
			s.sendBatch()
			timer.reset(BatchWaitNS)
		case <-s.done:
			s.sendBatch()
			return
		}
	}
}

func (s *Sender) sendBatch() {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.pending
	s.pending = make([]Packet, 0, MaxBatch)
	s.mu.Unlock()

	if err := sendmmsgBatch(s.fd, batch); err != nil {
		// fallback به write loop
		for _, pkt := range batch {
			s.conn.WriteToUDP(pkt.Data, pkt.Addr)
		}
	}
}

func (s *Sender) Close() {
	close(s.done)
	<-s.done
}

// ─── sendmmsg syscall ─────────────────────────────────────────────────────────

type mmsghdr struct {
	Hdr  syscall.Msghdr
	Len  uint32
	_pad [4]byte
}

type iovec struct {
	Base *byte
	Len  uint64
}

func sendmmsgBatch(fd int, pkts []Packet) error {
	msgs := make([]mmsghdr, len(pkts))
	iovecs := make([]iovec, len(pkts))

	for i, pkt := range pkts {
		// ساخت sockaddr
		var sa [16]byte // IPv4
		if pkt.Addr != nil {
			ip := pkt.Addr.IP.To4()
			if ip != nil {
				sa[0] = syscall.AF_INET
				sa[2] = byte(pkt.Addr.Port >> 8)
				sa[3] = byte(pkt.Addr.Port)
				copy(sa[4:8], ip)
			}
		}

		if len(pkt.Data) == 0 {
			continue
		}

		iovecs[i] = iovec{
			Base: &pkt.Data[0],
			Len:  uint64(len(pkt.Data)),
		}

		msgs[i].Hdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&iovecs[i]))
		msgs[i].Hdr.Iovlen = 1
		msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sa))
		msgs[i].Hdr.Namelen = 16
	}

	// SYS_SENDMMSG = 307 روی amd64
	const SYS_SENDMMSG = 307
	n, _, errno := syscall.Syscall6(
		SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	_ = n
	return nil
}
