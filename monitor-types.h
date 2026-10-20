#pragma once

#define OPCODES_SIZE 64
#define OPCODES_PROLOGUE_SIZE 42

#if defined(__bpf__) || defined(__BPF__)
#include "vmlinux.h"
#else
// TODO: how to do this properly?
#include <linux/types.h>
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 s64;
#endif

struct opcode_list {
    u8 opcodes[OPCODES_SIZE];
    s64 err;  // 0 = success, 1 = skipped on purpose, negative = bpf_probe_read_user error
};

struct pf_info {
    u32 cpu;
    u64 cr2;
    u64 err;
    u64 tai;
    u64 ip;

    struct opcode_list opcodes_ip;
};

struct cpu_migration_info {
    int from;
    int to;
    u64 tai; // time atomic international
};
