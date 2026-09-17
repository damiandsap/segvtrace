#pragma once

#include "monitor-types.h"
#include <bpf/bpf_helpers.h>

static inline void split_2u32(u64 in, u32* lower, u32* upper)
{
    *lower = (u32)in;
    *upper = (u32)(in >> 32);
}

static inline void get_opcodes(void *addr, struct opcode_list *list)
{
    for (u32 i = 0; i < OPCODES_SIZE; i++)
        list->opcodes[i] = 0;

    list->err = bpf_probe_read_user(list->opcodes, OPCODES_SIZE, addr);
}

