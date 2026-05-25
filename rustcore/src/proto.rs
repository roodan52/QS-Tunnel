//! Proto — packet encode/decode
//!
//! UDP header format (9 bytes):
//!   [0..3]  StreamID (24-bit big-endian در 3 byte)
//!   [3..7]  Seq (24-bit big-endian در 3 byte)  
//!   [6]     Flags
//!   [7..9]  Magic (0xAB, 0xCD)
//!
//! TCP header format (6 bytes):
//!   [0..3]  StreamID (24-bit)
//!   [3]     MsgType
//!   [4..6]  PayloadLen (16-bit big-endian)

use std::slice;

pub const UDP_HDR_SIZE: usize = 9;
pub const TCP_HDR_SIZE: usize = 6;
pub const UDP_MAGIC_0: u8 = 0xAB;
pub const UDP_MAGIC_1: u8 = 0xCD;

/// encode_udp — UDP packet رو encode میکنه
/// dst باید حداقل UDP_HDR_SIZE + payload_len بایت داشته باشه
/// Return: تعداد بایت نوشته شده، یا 0 در صورت خطا
#[no_mangle]
pub unsafe extern "C" fn qs_encode_udp(
    dst: *mut u8, dst_len: usize,
    stream_id: u32, seq: u32, flags: u8,
    payload: *const u8, payload_len: usize,
) -> usize {
    let total = UDP_HDR_SIZE + payload_len;
    if dst_len < total || dst.is_null() { return 0; }

    let out = slice::from_raw_parts_mut(dst, total);

    // StreamID: 3 bytes big-endian (24-bit)
    out[0] = ((stream_id >> 16) & 0xFF) as u8;
    out[1] = ((stream_id >>  8) & 0xFF) as u8;
    out[2] = ( stream_id        & 0xFF) as u8;

    // Seq: 3 bytes big-endian (24-bit)
    out[3] = ((seq >> 16) & 0xFF) as u8;
    out[4] = ((seq >>  8) & 0xFF) as u8;
    out[5] = ( seq        & 0xFF) as u8;

    // Flags + Magic
    out[6] = flags;
    out[7] = UDP_MAGIC_0;
    out[8] = UDP_MAGIC_1;

    // Payload — memcpy از libc (سریع‌ترین راه)
    if payload_len > 0 && !payload.is_null() {
        std::ptr::copy_nonoverlapping(payload, out.as_mut_ptr().add(UDP_HDR_SIZE), payload_len);
    }
    total
}

/// decode_udp — UDP header رو decode میکنه
/// Return: 1 اگه موفق، 0 اگه خطا (magic نادرست یا کوتاه)
#[no_mangle]
pub unsafe extern "C" fn qs_decode_udp(
    src: *const u8, src_len: usize,
    out_stream_id: *mut u32,
    out_seq: *mut u32,
    out_flags: *mut u8,
    out_payload_start: *mut usize,
) -> i32 {
    if src_len < UDP_HDR_SIZE || src.is_null() { return 0; }
    let buf = slice::from_raw_parts(src, src_len);

    // magic check
    if buf[7] != UDP_MAGIC_0 || buf[8] != UDP_MAGIC_1 { return 0; }

    if !out_stream_id.is_null() {
        *out_stream_id = ((buf[0] as u32) << 16)
                       | ((buf[1] as u32) <<  8)
                       |  (buf[2] as u32);
    }
    if !out_seq.is_null() {
        *out_seq = ((buf[3] as u32) << 16)
                 | ((buf[4] as u32) <<  8)
                 |  (buf[5] as u32);
    }
    if !out_flags.is_null() { *out_flags = buf[6]; }
    if !out_payload_start.is_null() { *out_payload_start = UDP_HDR_SIZE; }
    1
}

/// encode_tcp_hdr — TCP header رو encode میکنه (6 bytes)
#[no_mangle]
pub unsafe extern "C" fn qs_encode_tcp_hdr(
    dst: *mut u8, dst_len: usize,
    stream_id: u32, msg_type: u8, payload_len: u16,
) -> i32 {
    if dst_len < TCP_HDR_SIZE || dst.is_null() { return 0; }
    let out = slice::from_raw_parts_mut(dst, TCP_HDR_SIZE);
    out[0] = ((stream_id >> 16) & 0xFF) as u8;
    out[1] = ((stream_id >>  8) & 0xFF) as u8;
    out[2] = ( stream_id        & 0xFF) as u8;
    out[3] = msg_type;
    out[4] = (payload_len >> 8) as u8;
    out[5] = (payload_len & 0xFF) as u8;
    1
}

/// decode_tcp_hdr — TCP header رو decode میکنه
#[no_mangle]
pub unsafe extern "C" fn qs_decode_tcp_hdr(
    src: *const u8, src_len: usize,
    out_stream_id: *mut u32,
    out_msg_type: *mut u8,
    out_payload_len: *mut u16,
) -> i32 {
    if src_len < TCP_HDR_SIZE || src.is_null() { return 0; }
    let buf = slice::from_raw_parts(src, src_len);
    if !out_stream_id.is_null() {
        *out_stream_id = ((buf[0] as u32) << 16)
                       | ((buf[1] as u32) <<  8)
                       |  (buf[2] as u32);
    }
    if !out_msg_type.is_null()    { *out_msg_type = buf[3]; }
    if !out_payload_len.is_null() {
        *out_payload_len = ((buf[4] as u16) << 8) | (buf[5] as u16);
    }
    1
}
