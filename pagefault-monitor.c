#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "pagefault-monitor.skel.h"
#include "monitor-common.h"
#include "pagefault-monitor.h"

static volatile sig_atomic_t running = 1;

static struct cpu_topology cpu_topology;
static const char *cgroup_version;

static void handle_pf_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct pf_event_t *e = data;
    struct pf_info *pf = &e->pf;

    printf("{\"version\":{\"rev\":\"%s\",\"date\":\"%s\"},", GIT_REV, GIT_DATE);
    printf("\"cgroup\":\"%s\",", cgroup_version);
    printf("\"cpu\":%d,", pf->cpu);
    printf("\"tai\":%llu,", pf->tai);
    printf("\"process\":{\"rootns_pid\":%d,\"ns_pid\":%d,\"comm\":\"%s\"},", e->tgid, e->pidns_tgid, e->tgleader_comm);
    printf("\"thread\":{\"rootns_tid\":%d,\"ns_tid\":%d,\"comm\":\"%s\"},", e->pid, e->pidns_pid, e->comm);
    printf("\"page_fault\":");
    print_pf_info(pf, &cpu_topology);
    printf("}\n");

    fflush(stdout);
}

static void handle_lost_pf_event(void *ctx, int cpu, __u64 cnt)
{
    fprintf(stderr, "Lost %llu page fault events on CPU %d\n", cnt, cpu);

    fflush(stderr);
}

static void sigint_handler(int dummy)
{
    running = 0;
}

struct args {
    bool print_version;
};

static void parse_args(int argc, char **argv, struct args *args)
{
    args->print_version = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0)
            args->print_version = true;
    }
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

    cgroup_version = get_cgroup_version();
    fprintf(stderr, "[*] cgroup version: %s\n", cgroup_version);

    signal(SIGINT, sigint_handler);

    init_cpu_topology(&cpu_topology);

    struct pagefault_monitor_bpf *skel = pagefault_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    if (pagefault_monitor_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    if (pagefault_monitor_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    struct perf_buffer *pb = perf_buffer__new( bpf_map__fd(skel->maps.pf_events), 8, handle_pf_event, handle_lost_pf_event, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    fprintf(stderr, "[*] Monitoring all user-space page faults... (Ctrl+C to stop)\n");

    while (running)
        perf_buffer__poll(pb, 100);

    fprintf(stderr, "\b\b[*] Exiting the program...\n");

    free_cpu_topology(&cpu_topology);
    perf_buffer__free(pb);
    pagefault_monitor_bpf__destroy(skel);

    return 0;
}
