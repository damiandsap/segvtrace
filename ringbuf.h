#pragma once

#define DEFINE_RING_BUFFER(name, data_type, capacity) \
    struct name { \
        data_type data[capacity]; \
        u64 head; \
        u64 count; \
    }; \
    \
    static inline void name##_push(struct name* rb, data_type* value) \
    { \
        if (rb->head < capacity) { \
            rb->data[rb->head] = *value; \
            \
            if (++rb->head == capacity) { \
                rb->head = 0; \
            } \
            \
            if (rb->count < capacity) { \
                ++rb->count; \
            } \
        } \
    } \
    \
    /* i.e. passing an index 0 would return the oldest element in the ring buffer. */ \
    static inline data_type* name##_get(struct name* rb, u64 index) { \
        if (rb->count == capacity) { \
            index += rb->head; /* this makes index unbounded to the verifier */ \
        } \
        \
        /* establish bound for index; also helps if above index += ... needs to wrap around */ \
        index %= capacity; \
        \
        /* the compiler might fail to impose the upper bound, so state this exclusively */ \
        /* barrier_var(index); */ \
        /* if (index >= capacity) */ \
        /*     return 0; */ \
        /* \ */ \
        return rb->data + index; \
    }

