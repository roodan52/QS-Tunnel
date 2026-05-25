// Package sendpool — استخر sender با batch UDP (sendmmsg)
//
// بهینه‌سازی‌ها:
//   - هر worker پکت‌ها رو batch میکنه → sendmmsg → یه syscall برای N پکت
//   - per-stream routing → یه worker برای هر stream → ordering حفظ میشه
//   - fallback: اگه sendmmsg ناموفق شد → یکی‌یکی
package sendpool

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/Qteam-official/QS-Tunnel/internal/transport"
)

const batchMax = 32 // حداکثر پکت در یه sendmmsg

// Packet یه پکت برای ارسال
type Packet struct {
	StreamID uint32
	Data     []byte
	Dst      *net.UDPAddr
}

// Pool چند worker با batch send
type Pool struct {
	workers []*worker
	mask    uint32
	dropped atomic.Uint64
	sent    atomic.Uint64
}

type worker struct {
	tr    transport.Transport
	queue chan Packet
	done  chan struct{}
	pool  *Pool
	// batch buffers — یه بار alloc
	msgs  []mmsghdr
	iovs  []iov
	addrs [][16]byte
}

// Config
type Config struct {
	Workers   int
	QueueSize int
	Transport transport.Transport
}

func New(cfg Config) (*Pool, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 16384
	}

	n := 1
	for n < cfg.Workers {
		n <<= 1
	}

	p := &Pool{workers: make([]*worker, n), mask: uint32(n - 1)}
	for i := 0; i < n; i++ {
		w := &worker{
			tr:    cfg.Transport,
			queue: make(chan Packet, cfg.QueueSize),
			done:  make(chan struct{}),
			pool:  p,
			msgs:  make([]mmsghdr, batchMax),
			iovs:  make([]iov, batchMax),
			addrs: make([][16]byte, batchMax),
		}
		p.workers[i] = w
		go w.run()
	}
	return p, nil
}

func (p *Pool) Send(pkt Packet) {
	w := p.workers[pkt.StreamID&p.mask]
	select {
	case w.queue <- pkt:
	default:
		p.dropped.Add(1)
	}
}

func (p *Pool) Close() {
	for _, w := range p.workers {
		close(w.queue)
		<-w.done
	}
}

func (p *Pool) Stats() (sent, dropped uint64) {
	return p.sent.Load(), p.dropped.Load()
}

// ─── worker ──────────────────────────────────────────────────────────────────

func (w *worker) run() {
	defer close(w.done)
	batch := make([]Packet, 0, batchMax)

	for {
		// منتظر اولین پکت
		pkt, ok := <-w.queue
		if !ok {
			return
		}
		batch = append(batch[:0], pkt)

		// drain بقیه
	drain:
		for len(batch) < batchMax {
			select {
			case p, ok := <-w.queue:
				if !ok {
					w.sendBatch(batch)
					return
				}
				batch = append(batch, p)
			default:
				break drain
			}
		}

		w.sendBatch(batch)
	}
}

func (w *worker) sendBatch(pkts []Packet) {
	if len(pkts) == 0 {
		return
	}

	// اگه فقط یه پکت داریم، مستقیم بفرست
	if len(pkts) == 1 {
		if err := w.tr.Send(pkts[0].Dst, pkts[0].Data); err != nil {
			w.pool.dropped.Add(1)
		} else {
			w.pool.sent.Add(1)
		}
		return
	}

	// batch send با sendmmsg
	sent, err := w.trySendmmsg(pkts)
	if err != nil || sent < len(pkts) {
		// fallback برای باقیمانده
		for i := sent; i < len(pkts); i++ {
			if err := w.tr.Send(pkts[i].Dst, pkts[i].Data); err != nil {
				w.pool.dropped.Add(1)
			} else {
				w.pool.sent.Add(1)
			}
		}
	} else {
		w.pool.sent.Add(uint64(sent))
	}
}

func (w *worker) trySendmmsg(pkts []Packet) (int, error) {
	// دریافت raw UDP fd از transport
	udpConn, ok := w.tr.(interface{ RawUDPConn() *net.UDPConn })
	if !ok || udpConn == nil {
		return 0, syscall.ENOSYS
	}
	rawConn := udpConn.RawUDPConn()
	if rawConn == nil {
		return 0, syscall.ENOSYS
	}
	conn := rawConn

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var fd int
	raw.Control(func(f uintptr) { fd = int(f) })
	if fd == 0 {
		return 0, syscall.EBADF
	}

	n := len(pkts)
	if n > batchMax {
		n = batchMax
	}

	for i := 0; i < n; i++ {
		pkt := pkts[i]
		if len(pkt.Data) == 0 {
			continue
		}

		// IPv4 sockaddr_in
		addr := &w.addrs[i]
		*addr = [16]byte{}
		if pkt.Dst != nil {
			if ip4 := pkt.Dst.IP.To4(); ip4 != nil {
				(*addr)[1] = syscall.AF_INET // little-endian family
				(*addr)[2] = byte(pkt.Dst.Port >> 8)
				(*addr)[3] = byte(pkt.Dst.Port)
				copy((*addr)[4:8], ip4)
			}
		}

		w.iovs[i] = iov{Base: &pkt.Data[0], Len: uint64(len(pkt.Data))}
		w.msgs[i].Hdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&w.iovs[i]))
		w.msgs[i].Hdr.Iovlen = 1
		w.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(addr))
		w.msgs[i].Hdr.Namelen = 16
		w.msgs[i].Len = 0
	}

	const SYS_SENDMMSG = 307
	r, _, errno := syscall.Syscall6(
		SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&w.msgs[0])),
		uintptr(n),
		0, 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// ─── syscall types ───────────────────────────────────────────────────────────

type mmsghdr struct {
	Hdr  syscall.Msghdr
	Len  uint32
	_pad [4]byte
}

type iov struct {
	Base *byte
	Len  uint64
}

// ─── recvmmsg برای client ─────────────────────────────────────────────────────

// RecvBatch دریافت batch UDP پکت با recvmmsg
type RecvBatch struct {
	mu   sync.Mutex
	msgs []mmsghdr
	iovs []iov
	bufs [][]byte
}

func NewRecvBatch(n, bufSize int) *RecvBatch {
	rb := &RecvBatch{
		msgs: make([]mmsghdr, n),
		iovs: make([]iov, n),
		bufs: make([][]byte, n),
	}
	for i := range rb.bufs {
		rb.bufs[i] = make([]byte, bufSize)
		rb.iovs[i] = iov{Base: &rb.bufs[i][0], Len: uint64(bufSize)}
		rb.msgs[i].Hdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&rb.iovs[i]))
		rb.msgs[i].Hdr.Iovlen = 1
	}
	return rb
}

// Recv دریافت batch — fd باید UDP socket باشه
func (rb *RecvBatch) Recv(fd int) ([][]byte, error) {
	const SYS_RECVMMSG = 299
	n, _, errno := syscall.Syscall6(
		SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&rb.msgs[0])),
		uintptr(len(rb.msgs)),
		0, 0, 0,
	)
	if errno != 0 {
		return nil, errno
	}

	result := make([][]byte, n)
	for i := 0; i < int(n); i++ {
		result[i] = rb.bufs[i][:rb.msgs[i].Len]
	}
	return result, nil
}
