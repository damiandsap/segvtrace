/*
 * Sample program for sigsegv-monitor testing.
 * 
 * This program:
 * 1. Allocates several memory pages using mmap()
 * 2. Touches each page to trigger page faults
 * 3. Dereferences a null pointer to trigger SIGSEGV
 * 
 * The sigsegv-monitor should capture:
 * - Multiple page fault events (recorded in page_faults array)
 * - One SIGSEGV event with cr2 = 0 (null pointer)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define NUM_PAGES 4

/* Prevent compiler from optimizing away memory accesses */
volatile int sink;

int main(int argc, char *argv[]) {
    void *pages[NUM_PAGES];
    long page_size = sysconf(_SC_PAGESIZE);
    
    fprintf(stderr, "[sample_segfault] PID: %d\n", getpid());
    fprintf(stderr, "[sample_segfault] System page size: %ld\n", page_size);
    fprintf(stderr, "[sample_segfault] Allocating %d pages...\n", NUM_PAGES);
    
    /* Allocate pages - these won't cause page faults yet (no physical memory assigned) */
    for (int i = 0; i < NUM_PAGES; i++) {
        pages[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages[i] == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        fprintf(stderr, "[sample_segfault] Page %d allocated at %p\n", i, pages[i]);
    }
    
    fprintf(stderr, "[sample_segfault] Touching pages to trigger page faults...\n");
    
    /* Touch each page to trigger page faults (first access causes PF) */
    for (int i = 0; i < NUM_PAGES; i++) {
        volatile char *ptr = (volatile char *)pages[i];
        /* Write to trigger page fault */
        *ptr = (char)(i + 1);
        /* Read to ensure the write actually happened */
        sink = *ptr;
        fprintf(stderr, "[sample_segfault] Page %d touched at %p (wrote %d)\n", 
                i, pages[i], i + 1);
    }
    
    /* Output JSON on stdout with the expected page addresses for verification */
    printf("{\"page_size\":%ld,\"pages\":[", page_size);
    for (int i = 0; i < NUM_PAGES; i++) {
        if (i > 0) printf(",");
        printf("\"0x%lx\"", (unsigned long)pages[i]);
    }
    printf("],\"segfault_addr\":\"0x0\"}\n");
    fflush(stdout);
    
    /* Small delay to ensure page faults are recorded */
    usleep(10000);
    
    fprintf(stderr, "[sample_segfault] Triggering SIGSEGV via null pointer dereference...\n");
    
    /* Trigger SIGSEGV by dereferencing null pointer */
    volatile int *null_ptr = NULL;
    sink = *null_ptr;  /* This will cause SIGSEGV with cr2 = 0 */
    
    /* Should never reach here */
    fprintf(stderr, "[sample_segfault] ERROR: Should have crashed!\n");
    return 1;
}
