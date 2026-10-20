#pragma once

#include "monitor-types.h"

static inline void split_2u32(u64 in, u32* lower, u32* upper)
{
    *lower = (u32)in;
    *upper = (u32)(in >> 32);
}

