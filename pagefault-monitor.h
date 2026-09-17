#pragma once

#include "monitor-types.h"

struct pf_event_t {
    u32 tgid;
    u32 pidns_tgid;
    char tgleader_comm[16];

    u32 pid;
    u32 pidns_pid;
    char comm[16];

    struct pf_info pf;
};
