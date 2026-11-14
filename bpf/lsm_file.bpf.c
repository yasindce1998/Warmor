//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/file_open")
int BPF_PROG(lsm_file_check, struct file *file)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;

	// Read the file path from dentry — use nested BPF_CORE_READ to get
	// the name pointer directly, avoiding struct qstr layout mismatch.
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	if (!name)
		return 0;

	char fname_buf[64];
	int len = bpf_probe_read_kernel_str(fname_buf, sizeof(fname_buf), name);
	if (len <= 0)
		return 0;

	// A basename is not a policy path identity. Never consult policy_map,
	// even if an external raw-map writer installs a basename entry.
	emit_lsm_event(EVENT_TYPE_FILE, 0, fname_buf, len, cgid, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
