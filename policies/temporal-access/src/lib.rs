use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct Event {
    #[serde(rename = "type")]
    event_type: String,
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
    path: String,
    operation: String,
    remote_addr: String,
    remote_port: u16,
    parent_comm: String,
    // Temporal context sent by the host to ABI v3 policies: the event's wall
    // clock in UTC Unix seconds and the container's age in milliseconds. 0
    // means unknown (e.g. a host process has no container age).
    wall_clock_unix: u64,
    container_age_ms: u64,
}

const SECS_PER_DAY: u64 = 86_400;

impl Event {
    fn known_time(&self) -> Option<u64> {
        (self.wall_clock_unix > 0).then_some(self.wall_clock_unix)
    }

    /// UTC hour of day, if the time is known.
    fn hour_of_day(&self) -> Option<u8> {
        self.known_time().map(|t| ((t % SECS_PER_DAY) / 3600) as u8)
    }

    /// UTC weekday, 0 = Sunday ... 6 = Saturday (1970-01-01 was a Thursday).
    fn day_of_week(&self) -> Option<u8> {
        self.known_time().map(|t| ((t / SECS_PER_DAY + 4) % 7) as u8)
    }

    /// Container age in whole seconds, if known.
    fn container_age_secs(&self) -> Option<u64> {
        (self.container_age_ms > 0).then_some(self.container_age_ms / 1000)
    }

    fn age_over(&self, secs: u64) -> bool {
        self.container_age_ms > 0 && self.container_age_ms / 1000 > secs
    }

    fn hour_in(&self, start: u8, end: u8) -> Option<bool> {
        self.hour_of_day().map(|h| h >= start && h < end)
    }

    /// Mon-Fri within [start, end) hours UTC, if the time is known.
    fn within_hours(&self, start: u8, end: u8) -> Option<bool> {
        match (self.day_of_week(), self.hour_of_day()) {
            (Some(d), Some(h)) => Some((1..=5).contains(&d) && h >= start && h < end),
            _ => None,
        }
    }

    /// The maintenance window: Sunday 02:00-06:00 UTC. Unknown time is
    /// outside it, so maintenance tools fail closed.
    fn in_maintenance_window(&self) -> bool {
        matches!((self.day_of_week(), self.hour_of_day()), (Some(0), Some(h)) if (2..6).contains(&h))
    }
}

#[derive(Serialize)]
struct Decision {
    action: String,
    reason: String,
}

impl Decision {
    fn allow(reason: &str) -> Self {
        Decision { action: "allow".to_string(), reason: reason.to_string() }
    }
    fn deny(reason: &str) -> Self {
        Decision { action: "deny".to_string(), reason: reason.to_string() }
    }
    fn log(reason: &str) -> Self {
        Decision { action: "log".to_string(), reason: reason.to_string() }
    }
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

const STARTUP_WINDOW_SECS: u64 = 60;
const INIT_BINARIES: &[&str] = &[
    "/usr/bin/tini",
    "/sbin/tini",
    "/usr/local/bin/dumb-init",
    "/docker-entrypoint.sh",
    "/entrypoint.sh",
];

const MAINTENANCE_ONLY_TOOLS: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/yum",
    "/usr/bin/dnf",
    "/usr/bin/apk",
    "/usr/sbin/service",
    "/usr/bin/systemctl",
    "/usr/bin/pg_dump",
    "/usr/bin/mysqldump",
    "/usr/bin/mongodump",
];

const BUSINESS_HOURS_ONLY: &[&str] = &[
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/rsync",
    "/usr/bin/sftp",
];

const CRON_ALLOWED_HOURS: &[(u8, u8)] = &[
    (2, 4),   // Backup window: 02:00 - 04:00
    (6, 7),   // Log rotation: 06:00 - 07:00
];

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}

#[no_mangle]
pub extern "C" fn abi_version() -> u32 {
    // 3: the host sends wall_clock_unix and container_age_ms.
    3
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };

    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY,
    };

    let decision = evaluate_policy(&event);
    match decision.action.as_str() {
        "allow" => ACTION_ALLOW,
        "deny" => ACTION_DENY,
        "log" => ACTION_LOG,
        _ => ACTION_DENY,
    }
}

#[no_mangle]
pub extern "C" fn evaluate(event_json: *const c_char) -> *mut c_char {
    let event_str = unsafe {
        if event_json.is_null() {
            return CString::new(r#"{"action":"deny","reason":"null event"}"#)
                .unwrap()
                .into_raw();
        }
        match CStr::from_ptr(event_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                return CString::new(r#"{"action":"deny","reason":"invalid UTF-8"}"#)
                    .unwrap()
                    .into_raw()
            }
        }
    };

    let event: Event = match serde_json::from_str(event_str) {
        Ok(e) => e,
        Err(err) => {
            let msg = format!(r#"{{"action":"deny","reason":"parse error: {}"}}"#, err);
            return CString::new(msg).unwrap().into_raw();
        }
    };

    let decision = evaluate_policy(&event);
    let json = serde_json::to_string(&decision).unwrap_or_else(|_| {
        r#"{"action":"deny","reason":"serialization error"}"#.to_string()
    });
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            let _ = CString::from_raw(s);
        }
    }
}

fn evaluate_policy(event: &Event) -> Decision {
    match event.event_type.as_str() {
        "process" | "PROCESS" => evaluate_process(event),
        "file" | "FILE" => evaluate_file(event),
        "network" | "NETWORK" => evaluate_network(event),
        _ => Decision::log("Unknown event type"),
    }
}

fn evaluate_process(event: &Event) -> Decision {
    // Startup-only binaries: entrypoints/init systems allowed only during first 60s
    for init_bin in INIT_BINARIES {
        if event.filename.contains(init_bin) {
            if event.age_over(STARTUP_WINDOW_SECS) {
                return Decision::deny(&format!(
                    "Init binary {} not allowed after startup window ({}s)",
                    init_bin, STARTUP_WINDOW_SECS
                ));
            }
            return Decision::allow("Init binary during startup window");
        }
    }

    // Maintenance-only tools: only during maintenance windows
    for tool in MAINTENANCE_ONLY_TOOLS {
        if event.filename == *tool {
            if !event.in_maintenance_window() {
                return Decision::deny(&format!(
                    "{} only allowed during maintenance windows",
                    tool
                ));
            }
            return Decision::log(&format!("Maintenance tool {} during window", tool));
        }
    }

    // Business-hours-only tools (SSH, SCP): Mon-Fri 08:00-18:00
    for tool in BUSINESS_HOURS_ONLY {
        if event.filename == *tool {
            return match event.within_hours(8, 18) {
                Some(true) => Decision::allow("Within business hours"),
                Some(false) => Decision::deny(&format!(
                    "{} only allowed Mon-Fri 08:00-18:00 (current: day={:?}, hour={:?})",
                    tool, event.day_of_week(), event.hour_of_day()
                )),
                None => Decision::log(&format!("{} executed; time of day unknown", tool)),
            };
        }
    }

    // Cron-like processes only allowed during their scheduled windows
    if event.comm == "cron" || event.comm == "crond" || event.parent_comm == "cron" {
        let in_window = CRON_ALLOWED_HOURS
            .iter()
            .map(|(start, end)| event.hour_in(*start, *end))
            .try_fold(false, |acc, w| w.map(|w| acc || w));

        match in_window {
            Some(false) => {
                return Decision::deny(&format!(
                    "Cron execution outside allowed windows (hour={:?})",
                    event.hour_of_day()
                ))
            }
            None => return Decision::log("Cron execution; time of day unknown"),
            Some(true) => {}
        }
    }

    // After container startup (>5min), deny new binary first-execution
    if event.age_over(300) {
        let suspicious_first_exec_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/root/"];
        for path in &suspicious_first_exec_paths {
            if event.filename.starts_with(path) {
                return Decision::deny(&format!(
                    "New binary execution from {} after container stabilization period",
                    path
                ));
            }
        }
    }

    Decision::allow("No temporal violation")
}

fn evaluate_file(event: &Event) -> Decision {
    // Block config writes after startup period
    if event.age_over(STARTUP_WINDOW_SECS) {
        let config_paths = ["/etc/", "/usr/local/etc/", "/opt/conf/"];
        for cfg_path in &config_paths {
            if event.path.starts_with(cfg_path) && event.operation == "write" {
                return Decision::deny(&format!(
                    "Config modification of {} blocked after startup (container age: {}s)",
                    event.path, event.container_age_ms / 1000
                ));
            }
        }
    }

    // Log file access outside business hours (data exfiltration indicator)
    let sensitive_data_paths = ["/var/lib/data/", "/opt/data/", "/mnt/secrets/"];
    for data_path in &sensitive_data_paths {
        if event.path.starts_with(data_path) {
            if event.within_hours(8, 18) == Some(false) {
                return Decision::log(&format!(
                    "Sensitive data access outside business hours: {} (day={:?}, hour={:?})",
                    event.path, event.day_of_week(), event.hour_of_day()
                ));
            }
        }
    }

    // Backup operations only during backup window (02:00-04:00)
    let backup_indicators = [".bak", ".dump", ".sql", ".tar.gz", ".backup"];
    for indicator in &backup_indicators {
        if event.path.ends_with(indicator) && event.operation == "write" {
            if event.hour_in(2, 4) == Some(false) {
                return Decision::deny(&format!(
                    "Backup file creation outside window: {} (hour={:?})",
                    event.path, event.hour_of_day()
                ));
            }
        }
    }

    Decision::allow("No temporal file violation")
}

fn evaluate_network(event: &Event) -> Decision {
    // Block all outbound during container first 5 seconds (prevent container-start exfiltration)
    if let Some(age) = event.container_age_secs() {
        if age < 5 && event.remote_port != 53 {
            return Decision::deny(&format!(
                "Outbound network blocked during container initialization (age={}s)",
                age
            ));
        }
    }

    // Log network activity outside business hours
    if event.within_hours(6, 22) == Some(false) {
        // Allow critical infra ports even outside hours
        let always_allowed = [53, 443, 5432, 6379, 3306];
        if !always_allowed.contains(&event.remote_port) {
            return Decision::deny(&format!(
                "Non-critical network connection outside operating hours (port={}, hour={:?})",
                event.remote_port, event.hour_of_day()
            ));
        }
        return Decision::log(&format!(
            "Network activity outside business hours: {}:{} (hour={:?})",
            event.remote_addr, event.remote_port, event.hour_of_day()
        ));
    }

    Decision::allow("No temporal network violation")
}
