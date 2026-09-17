#pragma once

struct trace_event_raw_page_fault_user {
    struct trace_entry ent;
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
    char __data[0];
};

