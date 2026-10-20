#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include "pagefault-monitor.skel.h"
#include "monitor-common.h"
#include "pagefault-monitor.h"
#include "utils.h"

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t dump_buckets = 0;

static const char *cgroup_version;

static void print_bucket(struct pf_bucket_key *key, struct pf_bucket_val *val)
{
    u32 pid, tgid;
    split_2u32(key->pid_tgid, &pid, &tgid);

    u64 bucket_start_ns = key->bucket * BUCKET_TIME_SPAN;
    printf("{\"version\":{\"rev\":\"%s\",\"date\":\"%s\"},", GIT_REV, GIT_DATE);
    printf("\"cgroup\":\"%s\",", cgroup_version);
    printf("\"process\":{\"rootns_pid\":%d,\"ns_pid\":%d,\"comm\":\"%s\"},", tgid, val->pidns_tgid, val->tgleader_comm);
    printf("\"thread\":{\"rootns_tid\":%d,\"ns_tid\":%d,\"comm\":\"%s\"},", pid, val->pidns_pid, val->comm);
    printf("\"bucket\":{\"tai_start\":%llu,\"duration_ns\":%llu},", (unsigned long long)bucket_start_ns, (unsigned long long)BUCKET_TIME_SPAN);
    printf("\"page_fault_count\":%llu}\n", (unsigned long long)val->pf_count);
}

static void flush_buckets(int map_fd)
{
    struct pf_bucket_key cur, next;
    struct pf_bucket_val val;

    struct pf_bucket_key *key = NULL;

    while (bpf_map_get_next_key(map_fd, key, &next) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next, &val) == 0) {
            print_bucket(&next, &val);
        } else {
            fprintf(stderr, "Failed to find map entry for bucket: %llu, pid_tgid=%llu\n", (unsigned long long)next.bucket, (unsigned long long)next.pid_tgid);
        }

        cur = next;
        key = &cur;
    }

    fflush(stdout);
}

static void drain_expired_buckets(int map_fd, u64 current_bucket)
{
    struct pf_bucket_key cur, next;
    struct pf_bucket_val val;

    struct pf_bucket_key *key = NULL;

    while (bpf_map_get_next_key(map_fd, key, &next) == 0) {
        if (next.bucket < current_bucket) {
            if (bpf_map_lookup_elem(map_fd, &next, &val) == 0) {
                print_bucket(&next, &val);
                bpf_map_delete_elem(map_fd, &next);
                continue;
            } else {
                fprintf(stderr, "Failed to find map entry for bucket: %llu, pid_tgid=%llu\n", (unsigned long long)next.bucket, (unsigned long long)next.pid_tgid);
            }
        }

        cur = next;
        key = &cur;
    }

    fflush(stdout);
}

static void sigint_handler(int dummy)
{
    running = 0;
}

static void sigusr1_handler(int dummy)
{
    dump_buckets = 1;
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
    signal(SIGUSR1, sigusr1_handler);

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

    fprintf(stderr, "[*] Monitoring user-space page faults... (Ctrl+C to stop)\n");

    int map_fd = bpf_map__fd(skel->maps.pf_buckets);
    while (running) {
        struct timespec ts;
        ts.tv_sec = PRINT_INTERVAL / 1000000000;
        ts.tv_nsec = PRINT_INTERVAL % 1000000000;
        nanosleep(&ts, NULL);

        if (dump_buckets)
        {
            dump_buckets = 0;
            fprintf(stderr, "Print buckets requested from user...\n");
            flush_buckets(map_fd);
            fprintf(stderr, "DONE\n");
        }

        struct timespec tai;
        if (clock_gettime(CLOCK_TAI, &tai) != 0) {
            fprintf(stderr, "clock_gettime failed, errno=%d\n", errno);
        } else {
            u64 tai_ns = tai.tv_sec * 1000000000ull + tai.tv_nsec;
            u64 current_bucket = tai_ns / BUCKET_TIME_SPAN;
            drain_expired_buckets(map_fd, current_bucket);
        }
    }

    flush_buckets(map_fd);

    fprintf(stderr, "\b\b[*] Exiting the program...\n");

    pagefault_monitor_bpf__destroy(skel);

    return 0;
}
