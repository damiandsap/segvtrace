#pragma once

#define MAX_LBR_ENTRIES 32
#define MAX_USER_PF_ENTRIES 16
#define DISASM_SIZE 64
#define DISASM_PROLOGUE_SIZE 42

#define TRACE_PF_CR2
// #define TRACE_PF_CR2_INCREMENTAL
// #define TRACE_KERNEL_SPACE_BRANCHES

struct pf_info {
    u64 core;
    u64 cr2;
    u64 err;
    u64 tai;
};

struct user_regs_t {
    u64 rip;
    u64 rsp;
    u64 rax;
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 flags;
    u64 trapno;
    u64 err;
    u64 cr2;
};

struct disasm {
    u8 opcodes[DISASM_SIZE];
    s64 err;  // 0 = success, negative = bpf_probe_read_user error
};

// WARNING: this is for the SENDING process (e.g. pid) of the signal!
struct event_t {
    int signal;
    int si_code;

    u32 tgid; // the PROCESS id!
    u32 pidns_tgid; // the PROCESS id within the innermost pid namespace of the process
    char tgleader_comm[16]; // the PROCESS name

    u32 pid; // the THREAD id!
    u32 pidns_pid; // the THREAD id within the innermost pid namespace of the process
    char comm[16]; // the THREAD name

    u32 lbr_count;
    struct user_regs_t regs;
    struct perf_branch_entry lbr[MAX_LBR_ENTRIES];

    u64 tai; // time atomic international

    u32 pf_count;
    struct pf_info pf[MAX_USER_PF_ENTRIES];

    struct disasm disasm_ip;
    struct disasm disasm_last_jmp;
    u64 disasm_last_jmp_offset;
};
