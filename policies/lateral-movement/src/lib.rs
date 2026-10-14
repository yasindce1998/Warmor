use serde::Deserialize;
use std::slice;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Event {
    #[serde(rename = "PROCESS")]
    Process(ProcessEvent),
    #[serde(rename = "FILE")]
    File(FileEvent),
    #[serde(rename = "NETWORK")]
    Network(NetworkEvent),
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
    parent_comm: String,
    args: Vec<String>,
    cgroup_id: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct FileEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    operation: String,
    path: String,
    flags: u32,
    cgroup_id: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct NetworkEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    local_port: u16,
    direction: String,
    cgroup_id: u64,
    bytes_sent: u64,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

const REMOTE_ACCESS_TOOLS: &[&str] = &[
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/sbin/sshd",
    "/usr/bin/telnet",
    "/usr/bin/rsh",
    "/usr/bin/rlogin",
    "/usr/bin/rexec",
    "/usr/lib/openssh/ssh-keysign",
];

const CREDENTIAL_HARVESTING_TOOLS: &[&str] = &[
    "/usr/bin/mimikatz",
    "/usr/bin/secretsdump",
    "/usr/bin/hashdump",
    "/usr/bin/lazagne",
    "/usr/bin/crackmapexec",
    "/usr/bin/impacket-secretsdump",
    "/usr/bin/impacket-wmiexec",
    "/usr/bin/impacket-psexec",
    "/usr/bin/impacket-smbexec",
];

const DISCOVERY_TOOLS: &[&str] = &[
    "/usr/bin/nmap",
    "/usr/bin/masscan",
    "/usr/bin/zmap",
    "/usr/bin/arp-scan",
    "/usr/sbin/arp-scan",
    "/usr/bin/nbtscan",
    "/usr/bin/enum4linux",
    "/usr/bin/smbclient",
    "/usr/bin/rpcclient",
    "/usr/bin/ldapsearch",
];

const LATERAL_PORTS: &[u16] = &[
    22,    // SSH
    23,    // Telnet
    135,   // MSRPC
    139,   // NetBIOS
    445,   // SMB
    3389,  // RDP
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    2049,  // NFS
    111,   // Portmapper
    514,   // RSH
    512,   // Rexec
    513,   // Rlogin
];

const CREDENTIAL_FILE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/krb5.keytab",
    "/tmp/krb5cc_",
    "/var/lib/sss/db/",
    "/root/.ssh/id_",
    "/home/",
    "/etc/security/opasswd",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
];

const PIVOT_BINARIES: &[&str] = &[
    "/usr/bin/socat",
    "/usr/bin/chisel",
    "/usr/bin/ligolo",
    "/usr/bin/proxychains",
    "/usr/bin/proxychains4",
    "/usr/bin/revsocks",
    "/usr/bin/plink",
    "/usr/bin/stunnel",
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

    match event {
        Event::Process(e) => evaluate_process(&e),
        Event::File(e) => evaluate_file(&e),
        Event::Network(e) => evaluate_network(&e),
    }
}

fn evaluate_process(event: &ProcessEvent) -> i32 {
    // Block credential harvesting tools
    for tool in CREDENTIAL_HARVESTING_TOOLS {
        if event.filename == *tool || event.filename.ends_with(
            tool.rsplit('/').next().unwrap_or("")
        ) {
            return ACTION_DENY;
        }
    }

    // Block network discovery/scanning tools
    for tool in DISCOVERY_TOOLS {
        if event.filename == *tool {
            return ACTION_DENY;
        }
    }

    // Block tunneling/pivoting tools
    for tool in PIVOT_BINARIES {
        if event.filename == *tool || event.filename.ends_with(
            tool.rsplit('/').next().unwrap_or("")
        ) {
            return ACTION_DENY;
        }
    }

    // Block remote access tools in non-SSH containers
    for tool in REMOTE_ACCESS_TOOLS {
        if event.filename == *tool {
            return ACTION_DENY;
        }
    }

    // Detect pass-the-hash / kerberos abuse patterns
    if event.comm == "kinit" || event.comm == "klist" || event.comm == "kdestroy" {
        return ACTION_LOG;
    }

    // Detect WMI/PSExec-style execution (process spawned by remote service)
    let remote_exec_parents = ["wmiprvse", "wsmprovhost", "psexesvc", "winrshost"];
    for parent in &remote_exec_parents {
        if event.parent_comm == *parent {
            return ACTION_LOG;
        }
    }

    // Log SSH agent forwarding (can be used for lateral movement)
    if event.filename.contains("ssh-agent") || event.comm == "ssh-agent" {
        return ACTION_LOG;
    }

    // Detect suspicious argument patterns indicating lateral movement
    for arg in &event.args {
        // SSH with -o StrictHostKeyChecking=no (automated lateral movement)
        if arg.contains("StrictHostKeyChecking=no") {
            return ACTION_LOG;
        }
        // ProxyCommand (SSH tunneling for lateral movement)
        if arg.contains("ProxyCommand") || arg.contains("ProxyJump") {
            return ACTION_LOG;
        }
        // Port forwarding
        if arg == "-L" || arg == "-R" || arg == "-D" {
            return ACTION_LOG;
        }
    }

    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    // Block access to credential stores
    for cred_path in CREDENTIAL_FILE_PATHS {
        if event.path.starts_with(cred_path) || event.path == *cred_path {
            if event.operation == "read" && event.uid != 0 {
                return ACTION_DENY;
            }
            if event.operation == "write" {
                return ACTION_DENY;
            }
            return ACTION_LOG;
        }
    }

    // Block reading SSH private keys (credential theft for lateral movement)
    if event.path.ends_with("id_rsa")
        || event.path.ends_with("id_ecdsa")
        || event.path.ends_with("id_ed25519")
        || event.path.ends_with("id_dsa")
    {
        if event.uid != 0 {
            return ACTION_DENY;
        }
        return ACTION_LOG;
    }

    // Block reading .kube/config (Kubernetes lateral movement)
    if event.path.contains("/.kube/config") || event.path.contains("/.kube/cache/") {
        return ACTION_LOG;
    }

    // Block access to other services' secrets
    if event.path.starts_with("/run/secrets/") || event.path.starts_with("/var/run/secrets/") {
        if event.operation == "read" {
            return ACTION_LOG;
        }
    }

    // Block writing to SSH known_hosts (preparing for automated SSH)
    if event.path.ends_with("/known_hosts") && event.operation == "write" {
        return ACTION_LOG;
    }

    // Block reading /etc/hosts for internal host discovery
    if event.path == "/etc/hosts" && event.comm != "nginx" && event.comm != "envoy" {
        return ACTION_LOG;
    }

    // Detect creation of SSH config (lateral movement setup)
    if event.path.ends_with("/.ssh/config") && event.operation == "write" {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Block connections to lateral movement ports
    for port in LATERAL_PORTS {
        if event.remote_port == *port {
            // Allow SSH only from known admin subnets (simplified: only 10.0.0.x)
            if event.remote_port == 22 && event.remote_addr.starts_with("10.0.0.") {
                return ACTION_LOG;
            }
            return ACTION_DENY;
        }
    }

    // Detect internal network scanning (connection to many internal IPs)
    let is_internal = event.remote_addr.starts_with("10.")
        || event.remote_addr.starts_with("172.16.")
        || event.remote_addr.starts_with("172.17.")
        || event.remote_addr.starts_with("192.168.");

    if is_internal {
        // High-numbered ephemeral ports to internal hosts are suspicious
        if event.remote_port > 1024 && event.remote_port < 10000 {
            let common_service_ports: &[u16] = &[3000, 5000, 5432, 6379, 8080, 8443, 9090, 9200];
            if !common_service_ports.contains(&event.remote_port) {
                return ACTION_LOG;
            }
        }
    }

    // Block reverse shell callbacks to external addresses
    let c2_ports: &[u16] = &[4444, 4445, 5555, 6666, 7777, 8888, 9001, 9002, 1234, 1337, 31337];
    if c2_ports.contains(&event.remote_port) {
        return ACTION_DENY;
    }

    // Block SOCKS proxy ports (tunneling for lateral movement)
    let proxy_ports: &[u16] = &[1080, 1081, 9050, 9051, 8118];
    if proxy_ports.contains(&event.remote_port) {
        return ACTION_DENY;
    }

    // Log large outbound transfers to internal hosts (data staging)
    if is_internal && event.bytes_sent > 10_000_000 {
        return ACTION_LOG;
    }

    // Block connections to the Kubernetes API from non-system pods
    if event.remote_port == 6443 && event.uid >= 1000 {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}
