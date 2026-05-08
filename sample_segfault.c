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

/*
 * Naked function that triggers SIGSEGV via inline assembly.
 * The faulting mov instruction is at offset 16 from function start,
 * surrounded by unique identifiable instructions on both sides:
 *
 * Offset 0:  xorl %eax, %eax      (2 bytes) - zero rax for the fault
 * Offset 2:  jmp .Lfault           (2 bytes) - skip over pre-fault signature
 * Offset 4:  <pre-fault signature> (12 bytes) - unique, never executed
 * Offset 16: movl %eax, (%rax)     (2 bytes) - FAULTS HERE (RIP)
 * Offset 18: <post-fault signature>(12 bytes) - unique, never executed
 *
 * A 32-byte snapshot centered on RIP captures the full function.
 */
__attribute__((naked, noinline))
void trigger_segfault(void) {
    __asm__ volatile (
        /* Zero rax (needed for the fault address) */
        "xorl %%eax, %%eax\n\t"
        /* Short jump over pre-fault signature to the faulting instruction */
        ".byte 0xeb, 0x0c\n\t"  /* jmp short +12 (2 bytes) */
        /* Pre-fault signature: 12 bytes of unique instructions (never executed) */
        "bswap %%r13d\n\t"           /* 3 bytes: 41 0f cd */
        "btc %%r14, %%r15\n\t"       /* 4 bytes: 4d 0f bb f7 */
        "pdep %%r12, %%r13, %%r14\n\t" /* 5 bytes: c4 42 93 f5 f4 */
        /* Faulting instruction at offset 16 */
        "movl %%eax, (%%rax)\n\t"
        /* Post-fault signature: 12 bytes of unique instructions (never executed) */
        "rorx $0x1b, %%ebx, %%ecx\n\t" /* 6 bytes: c4 e3 7b f0 cb 1b */
        "adox %%r10, %%r11\n\t"        /* 6 bytes: f3 4d 0f 38 f6 da */
        ::: "memory"
    );
}

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

    fprintf(stderr, "[sample_segfault] Triggering SIGSEGV via naked function...\n");

    /* Trigger SIGSEGV in dedicated naked function */
    trigger_segfault();

    /* Should never reach here */
    fprintf(stderr, "[sample_segfault] ERROR: Should have crashed!\n");
    return 1;
}
