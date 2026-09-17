#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "monitor-types.bpf.h"
#include "pagefault-monitor.h"
#include "monitor-common.bpf.h"

// Output map (for user space)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} pf_events SEC(".maps");

// pf_event_t is too large for the eBPF stack — one entry per CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pf_event_t);
} pf_heap SEC(".maps");

SEC("tracepoint/exceptions/page_fault_user")
int trace_all_page_faults(struct trace_event_raw_page_fault_user *ctx)
{
    u32 key = 0;
    struct pf_event_t *event = bpf_map_lookup_elem(&pf_heap, &key);
    if (!event)
        return 0;

    split_2u32(bpf_get_current_pid_tgid(), &event->pid, &event->tgid);

    struct task_struct* task = bpf_get_current_task_btf();
    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &task->comm);
    bpf_probe_read_kernel_str(&event->tgleader_comm, sizeof(event->tgleader_comm), &task->group_leader->comm);
    // TODO: can the acquisition of pidns_tgid, pidns_pid be made more robust / simplified?
    {
        struct pid const* thread_pid = task->thread_pid;
        unsigned int const level = thread_pid->level;
        // thread_pid->numbers is a size-one flexible array member (type numbers[1])
        // => cannot perform bounds-check against BTF information
        // => need bpf_probe_read_kernel to read from indices potentially > 1
        struct upid const* upid_inv = &thread_pid->numbers[level];
        event->pidns_pid = BPF_CORE_READ(upid_inv, nr); // we already have implicit CO-RE, but we need the probe function call
    }
    {
        struct pid const* tgid_pid = task->signal->pids[PIDTYPE_TGID];
        unsigned int const level = tgid_pid->level;
        struct upid const* tgid_upid_inv = &tgid_pid->numbers[level];
        // TODO: doesn't this return the pid in the NS of the tg leader, instead of the pid in the NS of the current thread?
        // TODO: don't we need RCU here?
        event->pidns_tgid = BPF_CORE_READ(tgid_upid_inv, nr);
    }

    struct pf_info *pf = &event->pf;
    pf->cpu = bpf_get_smp_processor_id();
    pf->cr2 = ctx->address;
    pf->ip = ctx->ip;
    pf->err = ctx->error_code;
    pf->tai = bpf_ktime_get_tai_ns();
    pf->opcodes_ip.err = 1;
    if (ctx->ip != ctx->address)
        get_opcodes((void*)(ctx->ip - OPCODES_PROLOGUE_SIZE), &pf->opcodes_ip);

    // BPF_F_CURRENT_CPU -> "index of current core should be used"
    bpf_perf_event_output(ctx, &pf_events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
