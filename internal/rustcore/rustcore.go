// Package rustcore — CGO bridge به Rust hot path
//
// این package توابع proto، reasm و crypto رو از Rust صدا میزنه
// اگه Rust library موجود نبود، fallback به Go پیاده‌سازی میکنه
package rustcore

/*
#cgo LDFLAGS: -L${SRCDIR}/../../rustcore/target/release -lqscore -ldl -lpthread -lm
#cgo CFLAGS: -O2

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// proto
extern size_t qs_encode_udp(uint8_t* dst, size_t dst_len,
    uint32_t stream_id, uint32_t seq, uint8_t flags,
    const uint8_t* payload, size_t payload_len);

extern int32_t qs_decode_udp(const uint8_t* src, size_t src_len,
    uint32_t* out_stream_id, uint32_t* out_seq,
    uint8_t* out_flags, size_t* out_payload_start);

extern int32_t qs_encode_tcp_hdr(uint8_t* dst, size_t dst_len,
    uint32_t stream_id, uint8_t msg_type, uint16_t payload_len);

extern int32_t qs_decode_tcp_hdr(const uint8_t* src, size_t src_len,
    uint32_t* out_stream_id, uint8_t* out_msg_type, uint16_t* out_payload_len);

// reasm
extern void* qs_reasm_new(uint32_t first_seq);
extern int32_t qs_reasm_push(void* ptr, uint32_t seq, uint8_t flags,
    const uint8_t* data, size_t data_len);
extern int32_t qs_reasm_pop(void* ptr, uint8_t* out_buf, size_t out_buf_len);
extern int32_t qs_reasm_pending(void* ptr);
extern void qs_reasm_stats(void* ptr, uint64_t* out_delivered, uint64_t* out_dropped);
extern void qs_reasm_close(void* ptr);
extern void qs_reasm_free(void* ptr);

// crypto
extern void* qs_aes_gcm_new(const uint8_t* key, size_t key_len);
extern int32_t qs_aes_gcm_seal(void* ctx,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plain, size_t plain_len,
    uint8_t* out, size_t out_len);
extern int32_t qs_aes_gcm_open(void* ctx,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* cipher, size_t cipher_len,
    uint8_t* out, size_t out_len);
extern void qs_aes_gcm_free(void* ctx);
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	UDPHdrSize  = 9
	TCPHdrSize  = 6
	TagSize     = 16
	KeySize     = 32
)

// ─── Proto ────────────────────────────────────────────────────────────────────

// EncodeUDP — UDP packet رو در dst مینویسه
// Return: تعداد بایت نوشته شده
func EncodeUDP(dst []byte, streamID, seq uint32, flags byte, payload []byte) int {
	if len(dst) < UDPHdrSize+len(payload) { return 0 }
	var payPtr *C.uint8_t
	if len(payload) > 0 {
		payPtr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}
	n := C.qs_encode_udp(
		(*C.uint8_t)(unsafe.Pointer(&dst[0])), C.size_t(len(dst)),
		C.uint32_t(streamID), C.uint32_t(seq), C.uint8_t(flags),
		payPtr, C.size_t(len(payload)),
	)
	return int(n)
}

// DecodeUDP — UDP header رو decode میکنه
func DecodeUDP(src []byte) (streamID, seq uint32, flags byte, payloadStart int, err error) {
	if len(src) < UDPHdrSize {
		return 0, 0, 0, 0, errors.New("too short")
	}
	var cSID, cSeq C.uint32_t
	var cFlags C.uint8_t
	var cPS C.size_t
	ret := C.qs_decode_udp(
		(*C.uint8_t)(unsafe.Pointer(&src[0])), C.size_t(len(src)),
		&cSID, &cSeq, &cFlags, &cPS,
	)
	if ret == 0 { return 0, 0, 0, 0, errors.New("invalid magic") }
	return uint32(cSID), uint32(cSeq), byte(cFlags), int(cPS), nil
}

// EncodeTCPHdr — TCP header رو در dst[0:6] مینویسه
func EncodeTCPHdr(dst []byte, streamID uint32, msgType byte, payloadLen int) bool {
	if len(dst) < TCPHdrSize { return false }
	return C.qs_encode_tcp_hdr(
		(*C.uint8_t)(unsafe.Pointer(&dst[0])), C.size_t(len(dst)),
		C.uint32_t(streamID), C.uint8_t(msgType), C.uint16_t(payloadLen),
	) == 1
}

// DecodeTCPHdr — TCP header رو decode میکنه
func DecodeTCPHdr(src []byte) (streamID uint32, msgType byte, payloadLen int, err error) {
	if len(src) < TCPHdrSize { return 0, 0, 0, errors.New("too short") }
	var cSID C.uint32_t
	var cType C.uint8_t
	var cLen C.uint16_t
	ret := C.qs_decode_tcp_hdr(
		(*C.uint8_t)(unsafe.Pointer(&src[0])), C.size_t(len(src)),
		&cSID, &cType, &cLen,
	)
	if ret == 0 { return 0, 0, 0, errors.New("decode failed") }
	return uint32(cSID), byte(cType), int(cLen), nil
}

// ─── Reasm ────────────────────────────────────────────────────────────────────

// RustReasm — wrapper برای Rust reassembler
type RustReasm struct {
	ptr unsafe.Pointer
}

// NewReasm — reassembler جدید میسازه
func NewReasm(firstSeq uint32) *RustReasm {
	return &RustReasm{ptr: C.qs_reasm_new(C.uint32_t(firstSeq))}
}

// Push — پکت push میکنه
// Return: true اگه in-order data آماده هست
func (r *RustReasm) Push(seq uint32, flags byte, data []byte) bool {
	if r.ptr == nil || len(data) == 0 { return false }
	ret := C.qs_reasm_push(
		r.ptr, C.uint32_t(seq), C.uint8_t(flags),
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
	)
	return ret == 1
}

// Pop — data آماده رو برمیگردونه (یا nil)
func (r *RustReasm) Pop(buf []byte) int {
	if r.ptr == nil || len(buf) == 0 { return 0 }
	n := C.qs_reasm_pop(
		r.ptr,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)),
	)
	return int(n)
}

// Pending — تعداد پکت‌های آماده
func (r *RustReasm) Pending() int {
	if r.ptr == nil { return 0 }
	return int(C.qs_reasm_pending(r.ptr))
}

// Stats — آمار
func (r *RustReasm) Stats() (delivered, dropped uint64) {
	if r.ptr == nil { return }
	var d, dr C.uint64_t
	C.qs_reasm_stats(r.ptr, &d, &dr)
	return uint64(d), uint64(dr)
}

// Close — میبنده
func (r *RustReasm) Close() {
	if r.ptr != nil { C.qs_reasm_close(r.ptr) }
}

// Free — حافظه آزاد میکنه
func (r *RustReasm) Free() {
	if r.ptr != nil {
		C.qs_reasm_free(r.ptr)
		r.ptr = nil
	}
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

// CryptoCtx — wrapper برای Rust crypto context
type CryptoCtx struct {
	ptr unsafe.Pointer
}

// NewCrypto — crypto context با key میسازه (key باید 32 بایت باشه)
func NewCrypto(key []byte) (*CryptoCtx, error) {
	if len(key) != KeySize { return nil, errors.New("key must be 32 bytes") }
	ptr := C.qs_aes_gcm_new((*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	if ptr == nil { return nil, errors.New("crypto init failed") }
	return &CryptoCtx{ptr: ptr}, nil
}

// Seal — رمزنگاری
func (c *CryptoCtx) Seal(nonce, aad, plain, out []byte) (int, error) {
	if c.ptr == nil { return 0, errors.New("nil ctx") }
	var aadPtr *C.uint8_t
	if len(aad) > 0 { aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0])) }
	n := C.qs_aes_gcm_seal(
		c.ptr,
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])), C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&plain[0])), C.size_t(len(plain)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)),
	)
	if n == 0 { return 0, errors.New("seal failed") }
	return int(n), nil
}

// Open — رمزگشایی
func (c *CryptoCtx) Open(nonce, aad, cipher, out []byte) (int, error) {
	if c.ptr == nil { return 0, errors.New("nil ctx") }
	var aadPtr *C.uint8_t
	if len(aad) > 0 { aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0])) }
	n := C.qs_aes_gcm_open(
		c.ptr,
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])), C.size_t(len(nonce)),
		aadPtr, C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&cipher[0])), C.size_t(len(cipher)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)),
	)
	if n < 0 { return 0, errors.New("authentication failed") }
	return int(n), nil
}

// Free — حافظه آزاد میکنه
func (c *CryptoCtx) Free() {
	if c.ptr != nil {
		C.qs_aes_gcm_free(c.ptr)
		c.ptr = nil
	}
}
