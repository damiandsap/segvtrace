#pragma once

#include "monitor-types.h"

// 1min
#define BUCKET_TIME_SPAN (60*1000000000ull)

// 1s
#define PRINT_INTERVAL 1000000000ull

struct pf_bucket_key
{
    u64 bucket;
    u64 pid_tgid;
};

struct pf_bucket_val
{
    u32 pidns_tgid;
    char tgleader_comm[16];

    u32 pidns_pid;
    char comm[16];

    u64 pf_count;
};

