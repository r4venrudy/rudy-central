// SPDX-License-Identifier: GPL-2.0-only
// Fixed tracepoints and helper-only metadata. No payload, arguments, path reads,
// arbitrary memory access, packet injection, or enforcement hooks.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct policy {
    __u64 deadline_ns;
    __u32 uid;
    __u32 max_events;
    __u32 agent_tgid;
    __u32 reserved;
};
struct counters {
    __u64 seen;
    __u64 emitted;
    __u64 ring_dropped;
    __u64 budget_dropped;
};
struct event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 kind;
    char comm[16];
};
_Static_assert(sizeof(struct event) == 48, "event ABI must be 48 bytes");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy);
} capture_policy SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} capture_stats SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int observe(__u32 kind) {
    __u32 zero = 0;
    struct policy *p = bpf_map_lookup_elem(&capture_policy, &zero);
    if (!p || !p->deadline_ns || bpf_ktime_get_ns() >= p->deadline_ns) return 0;
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u64 pid_tid = bpf_get_current_pid_tgid();
    if (uid != p->uid || (__u32)(pid_tid >> 32) == p->agent_tgid) return 0;
    struct counters *s = bpf_map_lookup_elem(&capture_stats, &zero);
    if (!s) return 0;
    __u64 index = __sync_fetch_and_add(&s->seen, 1);
    if (index >= p->max_events) {
        __sync_fetch_and_add(&s->budget_dropped, 1);
        return 0;
    }
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&s->ring_dropped, 1);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = pid_tid >> 32;
    e->tid = (__u32)pid_tid;
    e->uid = uid;
    e->kind = kind;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    __sync_fetch_and_add(&s->emitted, 1);
    return 0;
}
SEC("tracepoint/sched/sched_process_exec")
int process_exec(void *ctx) { return observe(1); }
SEC("tracepoint/sched/sched_process_exit")
int process_exit(void *ctx) { return observe(2); }
SEC("tracepoint/syscalls/sys_enter_connect")
int connect_attempt(void *ctx) { return observe(3); }
char LICENSE[] SEC("license") = "GPL";
