#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define TRACE_READ      0
#define TRACE_WRITE     1
#define TRACE_OPEN      2
#define TRACE_FSYNC     3

struct ext4_key {
  char command[16];
  u32 pid;
  u8 type;
};

struct val_t {
  u64 ts_us;
  u64 offset;
  struct file *fp;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, struct val_t);
} entryinfo SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct ext4_key);
  __type(value, u64);
} ext4size SEC(".maps");

SEC("kprobe/ext4_file_read_iter")
int BPF_KPROBE(trace_read_entry, struct kiocb *iocb)
{
    u64 id = bpf_get_current_pid_tgid();
    struct file *fp;
    if (bpf_core_field_exists(iocb->ki_filp)) {
        fp = BPF_CORE_READ(iocb, ki_filp);
    } else {
        return 0;
    }

    if (!fp)
        return 0;

    u64 offset = BPF_CORE_READ(iocb, ki_pos);
    struct val_t val = {.ts_us = bpf_ktime_get_ns(), .fp = fp, .offset = offset};
    bpf_map_update_elem(&entryinfo, &id, &val, BPF_NOEXIST);
    return 0;
}

static int trace_return(struct pt_regs *ctx, int type) {
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();
    valp = bpf_map_lookup_elem(&entryinfo, &id);
    if (!valp) {
        return 0;
    }

    bpf_map_delete_elem(&entryinfo, &id);

    u32 pid = id >> 32;
    struct ext4_key key = {.pid = pid, type = (u8)type};
    bpf_get_current_comm(&key.command, sizeof(key.command));
    u64 value = PT_REGS_RC(ctx);
    increment_map(&ext4size, &key, value);
    return 0;
}

SEC("kretprobe/ext4_file_read_iter")
int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, TRACE_READ);
}



char LICENSE[] SEC("license") = "GPL";