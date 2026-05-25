//! Reasm — reassembly پکت‌های UDP خارج از ترتیب
//!
//! از BinaryHeap<u32> + HashMap<u32, Entry> استفاده میکنه
//! BinaryHeap max-heap هست — برای min نگه داریم negative index نه، بلکه
//! از (u32::MAX - seq) استفاده میکنیم تا max-heap = min-seq باشه

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Mutex;

const MAX_BUFFERED: usize = 512;

struct Entry {
    data:  Vec<u8>,
    flags: u8,
}

struct Inner {
    next_seq: u32,
    closed:   bool,
    // max-heap روی (u32::MAX - seq) → کمترین seq = بزرگترین key
    heap: BinaryHeap<u32>,
    // ذخیره داده جدا از heap key
    buf:  HashMap<u32, Entry>,
    ready: VecDeque<Vec<u8>>,
    delivered: u64,
    dropped:   u64,
}

pub struct Reassembler {
    inner: Mutex<Inner>,
}

impl Reassembler {
    fn new(first_seq: u32) -> Self {
        Reassembler {
            inner: Mutex::new(Inner {
                next_seq:  first_seq,
                closed:    false,
                heap:      BinaryHeap::with_capacity(32),
                buf:       HashMap::with_capacity(32),
                ready:     VecDeque::with_capacity(64),
                delivered: 0,
                dropped:   0,
            }),
        }
    }

    fn push(&self, seq: u32, flags: u8, data: &[u8]) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.closed { return false; }

        if seq < g.next_seq {
            g.dropped += 1;
            return false;
        }

        if seq == g.next_seq {
            // in-order — مستقیم تحویل بده
            g.ready.push_back(data.to_vec());
            g.delivered += 1;
            g.next_seq += 1;
            flush(&mut g);
            return true;
        }

        // out-of-order
        if g.buf.len() < MAX_BUFFERED {
            // اگه قبلاً همین seq هست، ignore کن
            if !g.buf.contains_key(&seq) {
                g.buf.insert(seq, Entry { data: data.to_vec(), flags });
                // heap key = u32::MAX - seq → max-heap بزرگترین یعنی کمترین seq
                g.heap.push(u32::MAX - seq);
            }
        } else {
            g.dropped += 1;
        }
        false
    }

    fn pop(&self, out: &mut [u8]) -> Option<usize> {
        let mut g = self.inner.lock().unwrap();
        if let Some(data) = g.ready.pop_front() {
            if data.len() <= out.len() {
                out[..data.len()].copy_from_slice(&data);
                return Some(data.len());
            }
        }
        None
    }

    fn pending(&self) -> usize {
        self.inner.lock().unwrap().ready.len()
    }

    fn close(&self) {
        self.inner.lock().unwrap().closed = true;
    }

    fn stats(&self) -> (u64, u64) {
        let g = self.inner.lock().unwrap();
        (g.delivered, g.dropped)
    }
}

fn flush(g: &mut Inner) {
    loop {
        // top of heap = u32::MAX - seq → seq = u32::MAX - top
        let top_seq = match g.heap.peek() {
            Some(&key) => u32::MAX - key,
            None        => break,
        };

        if top_seq == g.next_seq {
            g.heap.pop();
            if let Some(e) = g.buf.remove(&top_seq) {
                g.ready.push_back(e.data);
                g.delivered += 1;
                g.next_seq += 1;
            }
        } else if top_seq < g.next_seq {
            // duplicate در heap
            g.heap.pop();
            g.buf.remove(&top_seq);
            g.dropped += 1;
        } else {
            break;
        }
    }
}

// ─── C API ───────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn qs_reasm_new(first_seq: u32) -> *mut Reassembler {
    Box::into_raw(Box::new(Reassembler::new(first_seq)))
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_push(
    ptr: *mut Reassembler,
    seq: u32, flags: u8,
    data: *const u8, data_len: usize,
) -> i32 {
    if ptr.is_null() { return 0; }
    let slice = if data.is_null() || data_len == 0 { &[] }
                else { std::slice::from_raw_parts(data, data_len) };
    if (*ptr).push(seq, flags, slice) { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_pop(
    ptr: *mut Reassembler,
    out_buf: *mut u8, out_buf_len: usize,
) -> i32 {
    if ptr.is_null() || out_buf.is_null() { return 0; }
    let out = std::slice::from_raw_parts_mut(out_buf, out_buf_len);
    match (*ptr).pop(out) { Some(n) => n as i32, None => 0 }
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_pending(ptr: *mut Reassembler) -> i32 {
    if ptr.is_null() { return 0; }
    (*ptr).pending() as i32
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_stats(
    ptr: *mut Reassembler,
    out_delivered: *mut u64, out_dropped: *mut u64,
) {
    if ptr.is_null() { return; }
    let (d, dr) = (*ptr).stats();
    if !out_delivered.is_null() { *out_delivered = d; }
    if !out_dropped.is_null()   { *out_dropped = dr; }
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_close(ptr: *mut Reassembler) {
    if !ptr.is_null() { (*ptr).close(); }
}

#[no_mangle]
pub unsafe extern "C" fn qs_reasm_free(ptr: *mut Reassembler) {
    if !ptr.is_null() { drop(Box::from_raw(ptr)); }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heap_key() {
        // چک: u32::MAX - seq کوچکترین seq رو بزرگترین key میکنه
        let mut h: BinaryHeap<u32> = BinaryHeap::new();
        for seq in [3u32, 1, 5, 2, 4] {
            h.push(u32::MAX - seq);
        }
        let mut order = vec![];
        while let Some(k) = h.pop() { order.push(u32::MAX - k); }
        assert_eq!(order, vec![1, 2, 3, 4, 5], "min-seq first: {:?}", order);
    }

    #[test]
    fn test_inorder() {
        let r = Reassembler::new(0);
        let mut buf = vec![0u8; 10];
        for i in 0u32..20 { r.push(i, 0, &[(i % 256) as u8]); }
        for i in 0u32..20 {
            let n = r.pop(&mut buf).unwrap_or(0);
            assert_eq!(n, 1, "seq {}", i);
            assert_eq!(buf[0], (i % 256) as u8, "seq {}", i);
        }
        let (d, dr) = r.stats();
        assert_eq!(d, 20); assert_eq!(dr, 0);
    }

    #[test]
    fn test_reverse_order() {
        let r = Reassembler::new(0);
        let mut buf = vec![0u8; 10];
        // push 9..1 → all in heap
        for i in (1u32..10).rev() { r.push(i, 0, &[i as u8]); }
        assert_eq!(r.pending(), 0, "nothing ready yet");
        // push 0 → flush all
        r.push(0, 0, &[0u8]);
        assert_eq!(r.pending(), 10, "all 10 ready");
        for i in 0u32..10 {
            let n = r.pop(&mut buf).unwrap_or(0);
            assert_eq!(n, 1, "seq {}", i);
            assert_eq!(buf[0], i as u8, "seq {}", i);
        }
    }

    #[test]
    fn test_gap_fill() {
        let r = Reassembler::new(0);
        let mut buf = vec![0u8; 10];
        r.push(0, 0, &[0]);
        r.push(2, 0, &[2]);
        r.push(1, 0, &[1]);
        for i in 0u32..3 {
            assert_eq!(r.pop(&mut buf), Some(1), "seq {}", i);
            assert_eq!(buf[0], i as u8, "seq {}", i);
        }
    }

    #[test]
    fn test_duplicate() {
        let r = Reassembler::new(0);
        let mut buf = vec![0u8; 10];
        r.push(0, 0, &[1]);
        r.push(0, 0, &[2]); // dup
        r.push(1, 0, &[3]);
        assert_eq!(r.pop(&mut buf), Some(1)); assert_eq!(buf[0], 1);
        assert_eq!(r.pop(&mut buf), Some(1)); assert_eq!(buf[0], 3);
        assert_eq!(r.pop(&mut buf), None);
        let (d, _) = r.stats();
        assert_eq!(d, 2);
    }

    #[test]
    fn test_large_burst() {
        let r = Reassembler::new(0);
        let mut buf = vec![0u8; 4];
        const N: u32 = 100;
        // push random permutation
        let mut order: Vec<u32> = (0..N).collect();
        // deterministic shuffle
        for i in (1..order.len()).rev() {
            order.swap(i, (i * 7 + 3) % (i + 1));
        }
        for &seq in &order { r.push(seq, 0, &seq.to_le_bytes()); }
        for i in 0..N {
            let n = r.pop(&mut buf).unwrap_or(0);
            assert_eq!(n, 4, "seq {}", i);
            assert_eq!(u32::from_le_bytes(buf[..4].try_into().unwrap()), i, "seq {}", i);
        }
        let (d, dr) = r.stats();
        assert_eq!(d, N as u64);
        assert_eq!(dr, 0);
    }

    #[test]
    fn test_close_and_free() {
        let r = Reassembler::new(0);
        r.push(0, 0, &[1]);
        r.close();
        r.push(1, 0, &[2]); // after close — should not panic
    }
}
