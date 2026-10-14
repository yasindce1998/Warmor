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
    flags: u32,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    local_port: u16,
    direction: String,
    container_name: String,
    namespace: String,
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

const ALLOWED_EGRESS_PORTS: &[u16] = &[
    53,    // DNS
    80,    // HTTP
    443,   // HTTPS
    5432,  // PostgreSQL
    6379,  // Redis
    3306,  // MySQL
    9092,  // Kafka
    4222,  // NATS
    8500,  // Consul
];

const ALLOWED_INGRESS_PORTS: &[u16] = &[
    8080,  // App HTTP
    8443,  // App HTTPS
    9090,  // Prometheus metrics
    3000,  // gRPC/internal
];

const BLOCKED_EGRESS_ADDRS: &[&str] = &[
    "169.254.169.254",  // Cloud metadata
    "0.0.0.0",          // Broadcast
    "255.255.255.255",  // Broadcast
];

const INTERNAL_CIDR_PREFIXES: &[&str] = &[
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
];

const DNS_RESOLVERS: &[&str] = &[
    "10.96.0.10",      // Kubernetes CoreDNS (default)
    "127.0.0.11",      // Docker embedded DNS
    "169.254.25.10",   // Node-local DNS
];

const ALLOWED_PROCESS_NAMES: &[&str] = &[
    "envoy",
    "nginx",
    "haproxy",
    "myservice",
    "node",
    "java",
    "python3",
    "go",
];

const NETWORK_TOOLS: &[&str] = &[
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/nmap",
    "/usr/bin/tcpdump",
    "/usr/bin/tshark",
    "/usr/sbin/tcpdump",
    "/usr/bin/socat",
    "/usr/bin/netstat",
    "/usr/bin/ss",
    "/usr/bin/dig",
    "/usr/bin/nslookup",
    "/usr/bin/host",
    "/usr/bin/traceroute",
    "/usr/bin/mtr",
    "/usr/bin/ping",
    "/usr/sbin/iptables",
    "/usr/sbin/ip6tables",
    "/usr/sbin/nftables",
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
    2
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
        _ => Decision::deny("Unknown event type in zero-trust policy"),
    }
}

fn evaluate_process(event: &Event) -> Decision {
    // Block network reconnaissance tools
    for tool in NETWORK_TOOLS {
        if event.filename == *tool {
            return Decision::deny(&format!("Network tool {} blocked by zero-trust policy", tool));
        }
    }

    // Only allow known process names to make network connections
    let is_known_process = ALLOWED_PROCESS_NAMES.iter().any(|p| event.comm == *p);
    if !is_known_process && event.filename.starts_with("/tmp/") {
        return Decision::deny("Unknown process from /tmp blocked");
    }

    // Block IP manipulation tools
    let ip_tools = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"];
    for tool in &ip_tools {
        if event.filename == *tool {
            return Decision::deny("IP route/address manipulation blocked");
        }
    }

    Decision::allow("Process allowed")
}

fn evaluate_file(event: &Event) -> Decision {
    // Block modification of network configuration
    let net_config_paths = [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/network/",
        "/etc/sysconfig/network-scripts/",
        "/etc/netplan/",
        "/etc/NetworkManager/",
    ];

    if event.operation == "write" || (event.flags & 0x3) != 0 {
        for cfg in &net_config_paths {
            if event.path.starts_with(cfg) || event.path == *cfg {
                return Decision::deny(&format!(
                    "Network config modification blocked: {}",
                    event.path
                ));
            }
        }
    }

    // Block modification of firewall rules
    let fw_paths = [
        "/etc/iptables/",
        "/etc/nftables.conf",
        "/etc/firewalld/",
        "/etc/ufw/",
    ];
    if event.operation == "write" || (event.flags & 0x3) != 0 {
        for fw in &fw_paths {
            if event.path.starts_with(fw) || event.path == *fw {
                return Decision::deny(&format!("Firewall config modification blocked: {}", event.path));
            }
        }
    }

    // Block access to other services' TLS keys
    if event.path.contains("/tls/") || event.path.contains("/certs/") {
        if event.path.contains("private") || event.path.ends_with(".key") {
            if event.uid != 0 {
                return Decision::deny(&format!(
                    "Non-root access to TLS private key: {}",
                    event.path
                ));
            }
            return Decision::log(&format!("TLS private key access: {}", event.path));
        }
    }

    Decision::allow("File access allowed")
}

fn evaluate_network(event: &Event) -> Decision {
    // Block connections to explicitly blocked addresses
    for blocked in BLOCKED_EGRESS_ADDRS {
        if event.remote_addr == *blocked {
            return Decision::deny(&format!(
                "Connection to blocked address {} denied",
                event.remote_addr
            ));
        }
    }

    // DNS: only allow to known resolvers
    if event.remote_port == 53 {
        let is_known_resolver = DNS_RESOLVERS.iter().any(|r| event.remote_addr == *r);
        if !is_known_resolver {
            // Allow internal DNS but log external
            let is_internal = INTERNAL_CIDR_PREFIXES.iter().any(|p| event.remote_addr.starts_with(p));
            if !is_internal {
                return Decision::deny(&format!(
                    "DNS to non-approved resolver {} blocked",
                    event.remote_addr
                ));
            }
        }
        return Decision::allow("DNS to approved resolver");
    }

    // Egress: only allow declared ports
    if event.direction == "egress" || event.direction.is_empty() {
        if !ALLOWED_EGRESS_PORTS.contains(&event.remote_port) {
            return Decision::deny(&format!(
                "Egress to undeclared port {} blocked (zero-trust)",
                event.remote_port
            ));
        }
    }

    // Ingress: only allow declared service ports
    if event.direction == "ingress" {
        if !ALLOWED_INGRESS_PORTS.contains(&event.local_port) {
            return Decision::deny(&format!(
                "Ingress on undeclared port {} blocked (zero-trust)",
                event.local_port
            ));
        }
    }

    // Block direct pod-to-pod on non-service ports (lateral movement)
    let is_internal = INTERNAL_CIDR_PREFIXES.iter().any(|p| event.remote_addr.starts_with(p));
    if is_internal && !ALLOWED_EGRESS_PORTS.contains(&event.remote_port) {
        return Decision::deny(&format!(
            "Internal connection to {}:{} blocked (not a declared dependency)",
            event.remote_addr, event.remote_port
        ));
    }

    // Log all external connections for audit
    if !is_internal && event.remote_addr != "127.0.0.1" && event.remote_addr != "::1" {
        return Decision::log(&format!(
            "External connection: {}:{}",
            event.remote_addr, event.remote_port
        ));
    }

    Decision::allow("Network connection allowed")
}
