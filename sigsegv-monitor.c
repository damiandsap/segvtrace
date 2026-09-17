#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include "sigsegv-monitor.skel.h"
#include "monitor-common.h"
#include "sigsegv-monitor.h"

#if defined(TRACE_PF_CR2) || defined(TRACE_CPU_MIGRATIONS)
#define NEEDS_CPU_TOPOLOGY
#endif

#ifdef NEEDS_CPU_TOPOLOGY
static struct cpu_topology cpu_topology;
#endif

static const char* cgroup_version;

static volatile sig_atomic_t running = 1;

// perf_event_open fd for every CPUs
static int *cpus_fd;

// TODO: do we need this to enable LBR? We take the samples from within the eBPF program...
static void setup_global_lbr(void)
{
    int num_cpus = get_nprocs_conf();
    fprintf(stderr, "[*] Activating LBR hardware on %d CPUs...\n", num_cpus);

    cpus_fd = malloc(sizeof(int) * num_cpus);
    if (!cpus_fd) {
        fprintf(stderr, "Unable to allocate memory for %d CPUs. Abort.", num_cpus);
        return;
    }

    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
    pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
    pe.disabled = 1;
    pe.exclude_hv = 1;
    pe.sample_period = ((uint64_t)1) << 62; // newer kernels don't activate LBR if this is zero

#ifdef TRACE_KERNEL_SPACE_BRANCHES
    pe.exclude_kernel = 0;
#else
    pe.exclude_kernel = 1;
#endif

    for_each_cpu(cpu) {
        //                                          pid     group_fs, flags
        int fd = syscall(__NR_perf_event_open, &pe, -1, cpu, -1, 0);

        if (fd < 0) {
            fprintf(stderr, "Failed to enable LBR on CPU %d (Root required?)\n", cpu);
            continue;
        }

        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        cpus_fd[cpu] = fd;
    }
}

static const char* signal_to_string(int signal)
{
    switch (signal) {
        case 4: return "SIGILL";
        case 11: return "SIGSEGV";
    }

    return NULL;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct event_t *e = data;
    const char* signal = signal_to_string(e->signal);

    printf("{\"version\":{\"rev\":\"%s\",\"date\":\"%s\"},", GIT_REV, GIT_DATE);
    printf("\"cgroup\":\"%s\",", cgroup_version);
    printf("\"cpu\":%d,", cpu);
    printf("\"tai\":%llu,", e->tai);
    printf("\"process\":{\"rootns_pid\":%d,\"ns_pid\":%d,\"comm\":\"%s\"},", e->tgid, e->pidns_tgid, e->tgleader_comm);
    printf("\"thread\":{\"rootns_tid\":%d,\"ns_tid\":%d,\"comm\":\"%s\"},", e->pid, e->pidns_pid, e->comm);
    if (signal) {
        printf("\"signal\":\"%s\",", signal);
    } else {
        printf("\"signal\":%d,", e->signal);
    }
    printf("\"si_code\":%d,", e->si_code);
    printf("\"registers\":{");
    printf("\"rax\":\"0x%016llx\",", e->regs.rax);
    printf("\"rbx\":\"0x%016llx\",", e->regs.rbx);
    printf("\"rcx\":\"0x%016llx\",", e->regs.rcx);
    printf("\"rdx\":\"0x%016llx\",", e->regs.rdx);
    printf("\"rsi\":\"0x%016llx\",", e->regs.rsi);
    printf("\"rdi\":\"0x%016llx\",", e->regs.rdi);
    printf("\"rbp\":\"0x%016llx\",", e->regs.rbp);
    printf("\"rsp\":\"0x%016llx\",", e->regs.rsp);
    printf("\"r8\":\"0x%016llx\",", e->regs.r8);
    printf("\"r9\":\"0x%016llx\",", e->regs.r9);
    printf("\"r10\":\"0x%016llx\",", e->regs.r10);
    printf("\"r11\":\"0x%016llx\",", e->regs.r11);
    printf("\"r12\":\"0x%016llx\",", e->regs.r12);
    printf("\"r13\":\"0x%016llx\",", e->regs.r13);
    printf("\"r14\":\"0x%016llx\",", e->regs.r14);
    printf("\"r15\":\"0x%016llx\",", e->regs.r15);
    printf("\"rip\":\"0x%016llx\",", e->regs.rip);
    printf("\"flags\":\"0x%016llx\",", e->regs.flags);
    printf("\"trapno\":\"0x%016llx\",", e->regs.trapno);
    printf("\"err\":\"0x%016llx\",", e->regs.err);
    printf("\"cr2\":\"0x%016llx\"", e->regs.cr2);
    printf("},");

    print_opcodes("ip_snapshot", &e->opcodes_ip, ',');
    print_opcodes("last_jmp_source_snapshot", &e->opcodes_last_jmp_source, ',');
    print_opcodes("last_jmp_target_snapshot", &e->opcodes_last_jmp_target, ',');

#ifdef TRACE_PF_CR2
    printf("\"page_faults\":[");
    for_each(i, e->pf_count) {
        print_pf_info(&e->pf[i], &cpu_topology);

        if (i + 1 != e->pf_count) {
            printf(",");
        }
    }
    printf("],");
#endif

#ifdef TRACE_CPU_MIGRATIONS
    printf("\"cpu_migrations\":[");
    for_each(i, e->migration_count)
    {
        int from_core = get_physical_core(&cpu_topology, e->migration[i].from);
        int from_package = get_package(&cpu_topology, e->migration[i].from);

        int to_core = get_physical_core(&cpu_topology, e->migration[i].to);
        int to_package = get_package(&cpu_topology, e->migration[i].to);

        printf("{\"tai\":%llu,\"from\":{\"cpu\":%d,\"core\":%d,\"package\":%d},\"to\":{\"cpu\":%d,\"core\":%d,\"package\":%d}}",
                e->migration[i].tai, e->migration[i].from, from_core, from_package, e->migration[i].to, to_core, to_package);

        if (i + 1 != e->migration_count) {
            printf(",");
        }
    }
    printf("],");
#endif

    printf("\"lbr\":[");
    int lbr_limit = (e->lbr_count < MAX_LBR_ENTRIES) ? e->lbr_count : MAX_LBR_ENTRIES;
    for_each(i, lbr_limit) {
        if (i > 0) printf(",");
        if (e->lbr[i].from == 0 && e->lbr[i].to == 0)
            printf("null");
        else
            printf("{\"from\":\"0x%llx\",\"to\":\"0x%llx\"}",
                (unsigned long long)e->lbr[i].from,
                (unsigned long long)e->lbr[i].to);
    }
    printf("]}\n");

    fflush(stdout);
}

static void handle_lost_event(void *ctx, int cpu, __u64 cnt)
{
    fprintf(stderr, "Lost %llu events on CPU %d\n", cnt, cpu);

    fflush(stderr);
}

static void sigint_handler(int dummy)
{
    running = 0;
}

static void clean(void)
{
    if (cpus_fd) {
        for_each_cpu(cpu) {
            ioctl(cpus_fd[cpu], PERF_EVENT_IOC_DISABLE, 0);
        }

        free(cpus_fd);
    }

#ifdef NEEDS_CPU_TOPOLOGY
    free_cpu_topology(&cpu_topology);
#endif
}

struct args {
    bool print_version;
    bool trace_kernel_logs;
};

static void parse_args(int argc, char **argv, struct args *args)
{
    args->print_version = false;
    args->trace_kernel_logs = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            args->print_version = true;
        }

        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--trace-kernel-logs") == 0) {
            args->trace_kernel_logs = true;
        }
    }
}

static void* kernel_tracing_proc(void *data)
{
    FILE *fp = data;

    char *line = NULL;
    size_t line_len = 0;
    ssize_t read_len;
    while ((read_len = getline(&line, &line_len, fp)) != -1) {
        fprintf(stderr, "%s", line);
    }

    fclose(fp);
    free(line);

    return (void*)0;
}

int main(int argc, char *argv[])
{
    struct args args;
    parse_args(argc, argv, &args);

    if (args.print_version) {
        print_version("", stdout);
        return 0;
    } else {
        print_version("[*] version ", stderr);
    }

    pthread_t tracing_thread;
    FILE *tracing_pipe_file;
    if (args.trace_kernel_logs) {
        tracing_pipe_file = fopen("/sys/kernel/tracing/trace_pipe", "r");
        if (!tracing_pipe_file) {
            fprintf(stderr, "Failed to open kernel tracing pipe\n");
            return 1;
        }

        if (pthread_create(&tracing_thread, NULL, kernel_tracing_proc, tracing_pipe_file) != 0) {
            fprintf(stderr, "Failed to spawn kernel log tracing thread\n");
            return 1;
        }
    }

    cgroup_version = get_cgroup_version();
    fprintf(stderr, "[*] cgroup version: %s\n", cgroup_version);

    // Stop running if CTRL+C is entered
    signal(SIGINT, sigint_handler);

#ifdef NEEDS_CPU_TOPOLOGY
    init_cpu_topology(&cpu_topology);
#endif

    // Enable LBR: seems it is working that way...
    setup_global_lbr();

    struct sigsegv_monitor_bpf *skel = sigsegv_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    if (sigsegv_monitor_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    if (sigsegv_monitor_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    struct perf_buffer* pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, handle_lost_event, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    fprintf(stderr, "[*] Monitoring for SIGSEGV... (Ctrl+C to stop)\n");

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    fprintf(stderr, "\b\b[*] Exiting the program...\n");

    if (args.trace_kernel_logs) {
        pthread_cancel(tracing_thread);
        pthread_join(tracing_thread, NULL);
        fclose(tracing_pipe_file);
    }

    perf_buffer__free(pb);
    sigsegv_monitor_bpf__destroy(skel);
    clean();

    return 0;
}
