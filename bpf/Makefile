CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
ARCH_DIR := $(shell uname -m)-linux-gnu
INCLUDES := -I/usr/include/bpf -I/usr/include/$(ARCH_DIR)

.PHONY: all clean gen-vmlinux

all: monitors lsm

gen-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: monitors lsm

monitors: execve_monitor.bpf.o openat_monitor.bpf.o connect_monitor.bpf.o

lsm: lsm_exec.bpf.o lsm_file.bpf.o lsm_connect.bpf.o lsm_bind.bpf.o lsm_listen.bpf.o lsm_ptrace.bpf.o lsm_mount.bpf.o lsm_integrity.bpf.o

execve_monitor.bpf.o: execve_monitor.bpf.c tracepoint_defs.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c execve_monitor.bpf.c -o execve_monitor.bpf.o

openat_monitor.bpf.o: openat_monitor.bpf.c tracepoint_defs.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c openat_monitor.bpf.c -o openat_monitor.bpf.o

connect_monitor.bpf.o: connect_monitor.bpf.c tracepoint_defs.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c connect_monitor.bpf.c -o connect_monitor.bpf.o

lsm_exec.bpf.o: lsm_exec.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_exec.bpf.c -o lsm_exec.bpf.o

lsm_file.bpf.o: lsm_file.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_file.bpf.c -o lsm_file.bpf.o

lsm_connect.bpf.o: lsm_connect.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_connect.bpf.c -o lsm_connect.bpf.o

lsm_bind.bpf.o: lsm_bind.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_bind.bpf.c -o lsm_bind.bpf.o

lsm_listen.bpf.o: lsm_listen.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_listen.bpf.c -o lsm_listen.bpf.o

lsm_ptrace.bpf.o: lsm_ptrace.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_ptrace.bpf.c -o lsm_ptrace.bpf.o

lsm_mount.bpf.o: lsm_mount.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_mount.bpf.c -o lsm_mount.bpf.o

lsm_integrity.bpf.o: lsm_integrity.bpf.c warmor_lsm.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
		-c lsm_integrity.bpf.c -o lsm_integrity.bpf.o

clean:
	rm -f *.o
