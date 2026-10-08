#include "monitor-common.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "monitor-types.bpf.h"
#include "pagefault-monitor.h"

// Output map (for user space)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pf_bucket_key);
    __type(value, struct pf_bucket_val);
} pf_buckets SEC(".maps");

SEC("tracepoint/exceptions/page_fault_user")
int trace_all_page_faults(struct trace_event_raw_page_fault_user *ctx)
{
    u64 tai = bpf_ktime_get_tai_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct pf_bucket_key key;
    key.bucket = tai / BUCKET_TIME_SPAN;
    key.pid_tgid = pid_tgid;

    struct pf_bucket_val *val = bpf_map_lookup_elem(&pf_buckets, &key);
    if (val) {
        __atomic_add_fetch(&val->pf_count, 1, __ATOMIC_RELAXED);
    } else {
        struct pf_bucket_val newVal;
        newVal.pf_count = 1;

        struct task_struct* task = bpf_get_current_task_btf();
        bpf_probe_read_kernel_str(&newVal.comm, sizeof(newVal.comm), &task->comm);
        bpf_probe_read_kernel_str(&newVal.tgleader_comm, sizeof(newVal.tgleader_comm), &task->group_leader->comm);
        // TODO: can the acquisition of pidns_tgid, pidns_pid be made more robust / simplified?
        {
            struct pid const* thread_pid = task->thread_pid;
            unsigned int const level = thread_pid->level;
            // thread_pid->numbers is a size-one flexible array member (type numbers[1])
            // => cannot perform bounds-check against BTF information
            // => need bpf_probe_read_kernel to read from indices potentially > 1
            struct upid const* upid_inv = &thread_pid->numbers[level];
            newVal.pidns_pid = BPF_CORE_READ(upid_inv, nr); // we already have implicit CO-RE, but we need the probe function call
        }
        {
            struct pid const* tgid_pid = task->signal->pids[PIDTYPE_TGID];
            unsigned int const level = tgid_pid->level;
            struct upid const* tgid_upid_inv = &tgid_pid->numbers[level];
            // TODO: doesn't this return the pid in the NS of the tg leader, instead of the pid in the NS of the current thread?
            // TODO: don't we need RCU here?
            newVal.pidns_tgid = BPF_CORE_READ(tgid_upid_inv, nr);
        }

        bpf_map_update_elem(&pf_buckets, &key, &newVal, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
