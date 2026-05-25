// Package zerocopy — انتقال داده بدون copy به user space
//
// splice(): TCP fd → pipe → UDP fd
// داده هیچوقت وارد user space نمیشه
// مناسب برای: TCP connection → UDP send
//
// محدودیت: فقط Linux، فقط وقتی داده زیاده (>4KB)
// برای پکت‌های کوچیک (مثل ACK)، overhead splice بیشتره
package zerocopy

import (
	"errors"
	"io"
	"net"
	"syscall"
	"unsafe"
)

const (
	// حداقل اندازه برای استفاده از splice
	// زیر این مقدار، memcpy سریع‌تره
	MinSpliceSize = 4096

	// SPLICE_F_MOVE | SPLICE_F_NONBLOCK
	spliceFlags = 1 | 2
)

var ErrSpliceNotSupported = errors.New("splice not supported on this platform")

// TCPToUDP: داده رو از TCP connection به UDP socket splice میکنه
// برای استفاده در download path: dstConn → UDP
func TCPToUDP(tcpConn *net.TCPConn, udpFd int, maxBytes int) (int64, error) {
	tcpRC, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, ErrSpliceNotSupported
	}

	// pipe برای واسطه splice
	var pipeFds [2]int
	if err := syscall.Pipe2(pipeFds[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
		return 0, ErrSpliceNotSupported
	}
	defer syscall.Close(pipeFds[0])
	defer syscall.Close(pipeFds[1])

	var total int64
	var tcpFd int
	tcpRC.Control(func(fd uintptr) { tcpFd = int(fd) })

	for total < int64(maxBytes) {
		remain := int64(maxBytes) - total
		if remain > 65536 {
			remain = 65536
		}

		// TCP → pipe (kernel copy)
		n1, err := spliceSyscall(tcpFd, pipeFds[1], int(remain))
		if err != nil {
			if err == syscall.EAGAIN {
				break
			}
			return total, err
		}
		if n1 == 0 {
			return total, io.EOF
		}

		// pipe → UDP (kernel copy)
		n2, err := spliceSyscall(pipeFds[0], udpFd, int(n1))
		if err != nil {
			return total, err
		}
		total += int64(n2)
	}
	return total, nil
}

func spliceSyscall(rfd, wfd, n int) (int, error) {
	// SYS_SPLICE = 275
	const SYS_SPLICE = 275
	r, _, errno := syscall.Syscall6(
		SYS_SPLICE,
		uintptr(rfd),
		0, // offset_in: nil (sequential)
		uintptr(wfd),
		0, // offset_out: nil
		uintptr(n),
		spliceFlags,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// CopyWithSplice: io.Copy با splice fallback
// اگه splice کار نکرد، به copy معمولی fallback میکنه
func CopyWithSplice(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	// چک میکنیم splice ممکنه؟
	tcpSrc, isTCP := src.(*net.TCPConn)
	if !isTCP {
		return io.CopyBuffer(dst, src, buf)
	}

	// دریافت fd مقصد
	type fdGetter interface {
		SyscallConn() (syscall.RawConn, error)
	}
	dstFD, hasFD := dst.(fdGetter)
	if !hasFD {
		return io.CopyBuffer(dst, tcpSrc, buf)
	}

	raw, err := dstFD.SyscallConn()
	if err != nil {
		return io.CopyBuffer(dst, tcpSrc, buf)
	}

	var dstfd int
	raw.Control(func(fd uintptr) { dstfd = int(fd) })

	return TCPToUDP(tcpSrc, dstfd, 1<<30)
}

// SetTCPSockOpts بهینه‌ترین TCP socket options برای throughput بالا
func SetTCPSockOpts(conn *net.TCPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		// TCP_NODELAY
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		// TCP_QUICKACK — ACK سریع
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 12, 1) // TCP_QUICKACK=12
		// SO_RCVBUF
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024)
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 256*1024)
	})
}

// SetUDPSockOpts بهینه‌ترین UDP socket options
func SetUDPSockOpts(conn *net.UDPConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		// SO_RCVBUF / SO_SNDBUF
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
		// SO_REUSEPORT — چند goroutine روی یه port
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1) // SO_REUSEPORT=15
	})
}

// RecvmmsgBatch: دریافت batch UDP با recvmmsg
// به جای N recvfrom، یه syscall برای همه
const MaxRecvBatch = 32

type RecvPacket struct {
	Data []byte
	N    int
}

type mmsghdr struct {
	Hdr  syscall.Msghdr
	Len  uint32
	_pad [4]byte
}

type iovec struct {
	Base *byte
	Len  uint64
}

// RecvBatch دریافت batch پکت‌های UDP
func RecvBatch(fd int, bufSize int) ([]RecvPacket, error) {
	bufs := make([][]byte, MaxRecvBatch)
	iovecs := make([]iovec, MaxRecvBatch)
	msgs := make([]mmsghdr, MaxRecvBatch)

	for i := range bufs {
		bufs[i] = make([]byte, bufSize)
		iovecs[i] = iovec{
			Base: &bufs[i][0],
			Len:  uint64(bufSize),
		}
		msgs[i].Hdr.Iov = (*syscall.Iovec)(unsafe.Pointer(&iovecs[i]))
		msgs[i].Hdr.Iovlen = 1
	}

	const SYS_RECVMMSG = 299
	n, _, errno := syscall.Syscall6(
		SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(MaxRecvBatch),
		0, 0, 0,
	)
	if errno != 0 {
		return nil, errno
	}

	result := make([]RecvPacket, n)
	for i := 0; i < int(n); i++ {
		result[i] = RecvPacket{
			Data: bufs[i],
			N:    int(msgs[i].Len),
		}
	}
	return result, nil
}
