//! Wire format shared with bpf/bpfsight.bpf.c (struct ev).
//! C side has `_Static_assert` pinning the same size on each build.

use serde::Serialize;

pub const KIND_EXEC: u32 = 1;
pub const KIND_FORK: u32 = 2;
pub const KIND_CONNECT: u32 = 3;
pub const KIND_ACCEPT: u32 = 4;
pub const KIND_OPEN: u32 = 5;
pub const KIND_CRED: u32 = 6;
pub const KIND_MODULE: u32 = 7;

pub const EVENT_SIZE: usize = 656;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub ts: u64,
    pub seq: u64,
    pub flags: u64,
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub ret: u32,
    pub dport: u32, // network byte order
    pub dfd: u32,
    pub family: u8,
    pub dip: [u8; 4],
    pub pad: [u8; 3],
    pub comm: [u8; 16],
    pub path: [u8; 192],
    pub args: [u8; 384],
}
const _: () = assert!(std::mem::size_of::<RawEvent>() == EVENT_SIZE);

pub fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl RawEvent {
    pub fn decode(buf: &[u8]) -> Option<RawEvent> {
        if buf.len() < EVENT_SIZE {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const RawEvent) })
    }

    pub fn comm(&self) -> String {
        cstr(&self.comm)
    }
    pub fn path(&self) -> String {
        cstr(&self.path)
    }
    /// exec argv: three fixed 128-byte slots, NUL-terminated; joined non-empty
    pub fn args(&self) -> String {
        let mut parts: Vec<&[u8]> = Vec::new();
        for slot in self.args.chunks(128) {
            let end = slot.iter().position(|&c| c == 0).unwrap_or(slot.len());
            if end > 0 {
                parts.push(&slot[..end]);
            }
        }
        let joined = parts.join(&b' ');
        String::from_utf8_lossy(&joined).into_owned()
    }
    pub fn daddr(&self) -> String {
        format!("{}.{}.{}.{}", self.dip[0], self.dip[1], self.dip[2], self.dip[3])
    }
    pub fn dport_h(&self) -> u32 {
        u16::from_be_bytes([self.dport as u8, (self.dport >> 8) as u8]) as u32
    }
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            KIND_EXEC => "exec",
            KIND_FORK => "fork",
            KIND_CONNECT => "connect",
            KIND_ACCEPT => "accept",
            KIND_OPEN => "open",
            KIND_CRED => "cred",
            KIND_MODULE => "module",
            _ => "unknown",
        }
    }
}

/// JSONL-facing record.
#[derive(Serialize, Clone)]
pub struct Event {
    pub ts: String, // ISO-8601 UTC
    pub ktime_ns: u64,
    pub seq: u64,
    pub kind: &'static str,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub path: String,
    pub args: String,
    pub daddr: String,
    pub dport: u32,
    pub ret: i64,
    pub flags: u64,
}

impl Event {
    pub fn from_raw(r: &RawEvent, wall_ns: u64) -> Event {
        Event {
            ts: iso_utc(wall_ns),
            ktime_ns: r.ts,
            seq: r.seq,
            kind: r.kind_name(),
            pid: r.pid,
            ppid: r.ppid,
            uid: r.uid,
            comm: r.comm(),
            path: r.path(),
            args: r.args(),
            daddr: if r.family == 2 { r.daddr() } else { String::new() },
            dport: if r.family == 2 { r.dport_h() } else { 0 },
            ret: r.ret as i32 as i64,
            flags: r.flags,
        }
    }
}

/// ktime (CLOCK_MONOTONIC-ish) -> UTC ISO-8601 using an offset computed at start.
pub fn wall_ns_from_ktime(k: u64, boot_realtime_ns: u64) -> u64 {
    boot_realtime_ns + k
}

pub fn iso_utc(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = (ns % 1_000_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        nanos / 1_000_000
    )
}

/// Howard Hinnant's civil_from_days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_epoch_and_leap() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00.000Z");
        // 2024-02-29T12:00:00Z
        let ns = 1_709_208_000u64 * 1_000_000_000;
        assert_eq!(iso_utc(ns), "2024-02-29T12:00:00.000Z");
        // 2026-11-15T00:00:00Z
        let ns = 1_794_700_800u64 * 1_000_000_000;
        assert_eq!(iso_utc(ns), "2026-11-15T00:00:00.000Z");
    }

    #[test]
    fn decode_cstr_and_ports() {
        let mut raw = [0u8; EVENT_SIZE];
        raw[24..28].copy_from_slice(&KIND_CONNECT.to_le_bytes());
        raw[44..48].copy_from_slice(&5354u32.to_le_bytes()); // 0x14EA -> port 9050 big-endian? check below
        raw[52] = 2;
        raw[53..57].copy_from_slice(&[127, 0, 0, 1]);
        raw[60..64].copy_from_slice(b"nc\0\0");
        let e = RawEvent::decode(&raw).unwrap();
        assert_eq!(e.kind_name(), "connect");
        assert_eq!(e.daddr(), "127.0.0.1");
        // dport field holds sin_port in network order: bytes [EA,14] -> 0xEA14? set explicitly instead
        raw[44] = 0xEA; // sin_port bytes in memory: 0xEA,0x14 = BE 0xEA14 = 59924? no:
        raw[45] = 0x14;
        raw[46] = 0;
        raw[47] = 0;
        let e = RawEvent::decode(&raw).unwrap();
        assert_eq!(e.dport_h(), 59924);
        let raw2 = [0u8; EVENT_SIZE];
        let e2 = RawEvent::decode(&raw2).unwrap();
        assert_eq!(e2.comm(), "");
        assert_eq!(e2.args(), "");
    }
}
