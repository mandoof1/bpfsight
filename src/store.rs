//! SQLite sink for events + alerts, batched inserts, stats queries.

use crate::events::Event;
use rusqlite::{params, Connection};

pub struct Store {
    pub con: Connection,
    pub events_in_tx: usize,
}

#[derive(serde::Serialize, Clone)]
pub struct AlertRow {
    pub ts: String,
    pub rule: String,
    pub title: String,
    pub severity: &'static str,
    pub pid: u32,
    pub comm: String,
    pub detail: String,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Store> {
        let con = Connection::open(path)?;
        con.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events(
               id INTEGER PRIMARY KEY, ts TEXT, ktime_ns INTEGER, seq INTEGER,
               kind TEXT, pid INTEGER, ppid INTEGER, uid INTEGER, comm TEXT,
               path TEXT, args TEXT, daddr TEXT, dport INTEGER, ret INTEGER, flags INTEGER);
             CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
             CREATE TABLE IF NOT EXISTS alerts(
               id INTEGER PRIMARY KEY, ts TEXT, rule TEXT, title TEXT, severity TEXT,
               pid INTEGER, comm TEXT, detail TEXT);",
        )?;
        con.execute("BEGIN", ())?;
        Ok(Store { con, events_in_tx: 0 })
    }

    pub fn event(&mut self, e: &Event) -> rusqlite::Result<()> {
        self.con.execute(
            "INSERT INTO events(ts,ktime_ns,seq,kind,pid,ppid,uid,comm,path,args,daddr,dport,ret,flags)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![e.ts, e.ktime_ns as i64, e.seq as i64, e.kind, e.pid as i64, e.ppid as i64,
                    e.uid as i64, e.comm, e.path, e.args, e.daddr, e.dport as i64, e.ret, e.flags as i64],
        )?;
        self.events_in_tx += 1;
        if self.events_in_tx >= 512 {
            self.commit()?;
        }
        Ok(())
    }

    pub fn commit(&mut self) -> rusqlite::Result<()> {
        if self.events_in_tx > 0 || self.con.is_autocommit() == false {
            self.con.execute_batch("COMMIT; BEGIN;")?;
            self.events_in_tx = 0;
        }
        Ok(())
    }

    pub fn alert(&mut self, a: &AlertRow) -> rusqlite::Result<()> {
        self.con.execute(
            "INSERT INTO alerts(ts,rule,title,severity,pid,comm,detail) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![a.ts, a.rule, a.title, a.severity, a.pid as i64, a.comm, a.detail],
        )?;
        Ok(())
    }
}

pub fn stats(con: &Connection) -> rusqlite::Result<String> {
    let mut out = String::new();
    let mut q = con.prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind ORDER BY 2 DESC")?;
    let rows: Vec<(String, i64)> =
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    out.push_str("events by kind:\n");
    for (k, n) in &rows {
        out.push_str(&format!("  {k:<10} {n}\n"));
    }
    let total: i64 = con.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let maxseq: i64 = con.query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0))?;
    out.push_str(&format!("total events: {total}\n"));
    // max seq is the current ring counter; across several runs sharing one
    // db file rows accumulate, so clamping to zero is the honest floor here
    out.push_str(&format!(
        "ring-buffer drops (this db): {}   (max seq {maxseq}, rows {total})\n",
        maxseq.saturating_sub(total)
    ));
    let mut q = con.prepare(
        "SELECT rule, COUNT(*), MAX(severity) FROM alerts GROUP BY rule ORDER BY 2 DESC",
    )?;
    let rows: Vec<(String, i64, String)> =
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    if !rows.is_empty() {
        out.push_str("alerts by rule:\n");
        for (r_, n, sev) in &rows {
            out.push_str(&format!("  {sev:<7} {r_:<24} {n}\n"));
        }
    }
    let mut q = con.prepare(
        "SELECT comm, COUNT(*) FROM events WHERE kind='exec' GROUP BY comm ORDER BY 2 DESC LIMIT 8",
    )?;
    let rows: Vec<(String, i64)> =
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    if !rows.is_empty() {
        out.push_str("top exec comm:\n");
        for (c, n) in &rows {
            out.push_str(&format!("  {c:<16} {n}\n"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;

    fn ev(kind: &str, pid: u32) -> Event {
        Event {
            ts: "2026-01-01T00:00:00.000Z".into(), ktime_ns: 1, seq: 0,
            kind: String::from(kind).leak(), pid, ppid: 1, uid: 0,
            comm: "sh".into(), path: "/bin/sh".into(), args: String::new(),
            daddr: String::new(), dport: 0, ret: 0, flags: 0,
        }
    }

    #[test]
    fn store_and_stats() {
        let path = std::env::temp_dir().join(format!("bpsdb-{}", std::process::id()));
        let mut st = Store::open(&path.to_string_lossy()).unwrap();
        st.event(&ev("exec", 1)).unwrap();
        st.event(&ev("exec", 2)).unwrap();
        st.event(&ev("connect", 3)).unwrap();
        st.alert(&AlertRow {
            ts: "t".into(), rule: "recon-tools".into(), title: "recon".into(),
            severity: "info", pid: 1, comm: "id".into(), detail: "id".into(),
        })
        .unwrap();
        st.commit().unwrap();
        st.con.close().unwrap();
        let con = rusqlite::Connection::open(&path).unwrap();
        let s = stats(&con).unwrap();
        assert!(s.contains("exec       2"), "{s}");
        assert!(s.contains("connect"), "{s}");
        assert!(s.contains("recon-tools"), "{s}");
        drop(con);
        let _ = std::fs::remove_file(path);
    }
}
