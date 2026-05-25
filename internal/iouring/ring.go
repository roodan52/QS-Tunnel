// Package iouring — async I/O با io_uring (Linux 5.1+)
//
// io_uring مزایا:
//   - هر I/O operation یه syscall نمیخواد
//   - submission و completion جدا هستن — pipeline
//   - fixed buffers — کاهش page fault
//   - registered files — کاهش fd lookup overhead
//
// برای sttunnel: async read از TCP connections
// به جای یه goroutine per connection، یه ring برای همه
package iouring

import (
	"errors"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	// IORING opcodes
	IORING_OP_NOP      = 0
	IORING_OP_READV    = 1
	IORING_OP_WRITEV   = 2
	IORING_OP_READ     = 22
	IORING_OP_WRITE    = 23
	IORING_OP_RECV     = 26
	IORING_OP_SEND     = 27
	IORING_OP_RECVMSG  = 13
	IORING_OP_SENDMSG  = 9

	// setup flags
	IORING_SETUP_SQPOLL = 0x2 // kernel polling thread
	IORING_SETUP_IOPOLL = 0x8 // I/O polling

	// SQE flags
	IOSQE_FIXED_FILE = 1 << 0

	// CQE flags
	IORING_CQE_F_MORE = 1 << 1
)

// SQE: Submission Queue Entry
type SQE struct {
	Opcode     uint8
	Flags      uint8
	IoPrio     uint16
	Fd         int32
	Off        uint64
	Addr       uint64
	Len        uint32
	OpcodeFlags uint32
	UserData   uint64
	Pad        [3]uint64
}

// CQE: Completion Queue Entry
type CQE struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// Ring یه io_uring instance
type Ring struct {
	fd       int
	sqRing   *sqRing
	cqRing   *cqRing
	sqEntries []SQE
}

type sqRing struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	flags       *uint32
	dropped     *uint32
	array       *uint32
}

type cqRing struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	overflow    *uint32
	cqes        *CQE
}

// io_uring_params
type params struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32
	sqOff        sqringOffsets
	cqOff        cqringOffsets
}

type sqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	userAddr    uint64
}

type cqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	userAddr    uint64
}

// New یه io_uring ring میسازه
func New(entries uint32) (*Ring, error) {
	p := &params{}

	// io_uring_setup syscall
	const SYS_IO_URING_SETUP = 425
	fd, _, errno := syscall.Syscall(
		SYS_IO_URING_SETUP,
		uintptr(entries),
		uintptr(unsafe.Pointer(p)),
		0,
	)
	if errno != 0 {
		return nil, &ErrRing{Op: "setup", Errno: errno}
	}

	ring := &Ring{fd: int(fd)}

	// map SQ ring
	sqSize := p.sqOff.array + p.sqEntries*4
	sqMem, err := mmap(int(fd), 0, int(sqSize), syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		syscall.Close(int(fd))
		return nil, err
	}

	ring.sqRing = &sqRing{
		head:        (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.head])),
		tail:        (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.tail])),
		ringMask:    (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.ringMask])),
		ringEntries: (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.ringEntries])),
		flags:       (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.flags])),
		dropped:     (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.dropped])),
		array:       (*uint32)(unsafe.Pointer(&sqMem[p.sqOff.array])),
	}

	// map SQE array
	sqeSize := p.sqEntries * 64 // sizeof(SQE) = 64
	sqeMem, err := mmap(int(fd), 0x10000000, int(sqeSize), syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		syscall.Close(int(fd))
		return nil, err
	}
	ring.sqEntries = (*[1 << 20]SQE)(unsafe.Pointer(&sqeMem[0]))[:p.sqEntries]

	// map CQ ring
	cqSize := p.cqOff.cqes + p.cqEntries*16 // sizeof(CQE) = 16
	cqMem, err := mmap(int(fd), 0x08000000, int(cqSize), syscall.PROT_READ|syscall.PROT_WRITE)
	if err != nil {
		syscall.Close(int(fd))
		return nil, err
	}

	ring.cqRing = &cqRing{
		head:        (*uint32)(unsafe.Pointer(&cqMem[p.cqOff.head])),
		tail:        (*uint32)(unsafe.Pointer(&cqMem[p.cqOff.tail])),
		ringMask:    (*uint32)(unsafe.Pointer(&cqMem[p.cqOff.ringMask])),
		ringEntries: (*uint32)(unsafe.Pointer(&cqMem[p.cqOff.ringEntries])),
		overflow:    (*uint32)(unsafe.Pointer(&cqMem[p.cqOff.overflow])),
		cqes:        (*CQE)(unsafe.Pointer(&cqMem[p.cqOff.cqes])),
	}

	return ring, nil
}

// SubmitRecv یه async recv operation submit میکنه
func (r *Ring) SubmitRecv(fd int, buf []byte, userData uint64) error {
	tail := atomic.LoadUint32(r.sqRing.tail)
	head := atomic.LoadUint32(r.sqRing.head)
	mask := *r.sqRing.ringMask

	if tail-head > *r.sqRing.ringEntries {
		return errors.New("SQ full")
	}

	idx := tail & mask
	sqe := &r.sqEntries[idx]
	*sqe = SQE{
		Opcode:   IORING_OP_RECV,
		Fd:       int32(fd),
		Addr:     uint64(uintptr(unsafe.Pointer(&buf[0]))),
		Len:      uint32(len(buf)),
		UserData: userData,
	}

	// update array
	arrayPtr := (*[1 << 20]uint32)(unsafe.Pointer(r.sqRing.array))
	arrayPtr[idx] = idx

	atomic.StoreUint32(r.sqRing.tail, tail+1)
	return nil
}

// Submit: submit همه pending SQE ها
func (r *Ring) Submit(waitNr uint32) (int, error) {
	const SYS_IO_URING_ENTER = 426
	n, _, errno := syscall.Syscall6(
		SYS_IO_URING_ENTER,
		uintptr(r.fd),
		uintptr(atomic.LoadUint32(r.sqRing.tail)-atomic.LoadUint32(r.sqRing.head)),
		uintptr(waitNr),
		0, 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// PeekCQE یه completion event میگیره بدون block
func (r *Ring) PeekCQE() (*CQE, bool) {
	head := atomic.LoadUint32(r.cqRing.head)
	tail := atomic.LoadUint32(r.cqRing.tail)
	if head == tail {
		return nil, false
	}
	mask := *r.cqRing.ringMask
	cqePtr := (*[1 << 20]CQE)(unsafe.Pointer(r.cqRing.cqes))
	cqe := &cqePtr[head&mask]
	atomic.StoreUint32(r.cqRing.head, head+1)
	return cqe, true
}

// WaitCQE: منتظر حداقل n completion میمونه
func (r *Ring) WaitCQE(n uint32) error {
	_, err := r.Submit(n)
	return err
}

// Close ring رو میبنده
func (r *Ring) Close() error {
	return syscall.Close(r.fd)
}

// mmap helper
func mmap(fd int, offset int64, length int, prot int) ([]byte, error) {
	const MAP_SHARED = 0x01
	const IORING_OFF_SQ_RING = 0
	_ = IORING_OFF_SQ_RING
	return syscall.Mmap(fd, offset, length, prot, MAP_SHARED)
}

// ErrRing خطای io_uring
type ErrRing struct {
	Op    string
	Errno syscall.Errno
}

func (e *ErrRing) Error() string {
	return "io_uring " + e.Op + ": " + e.Errno.Error()
}
