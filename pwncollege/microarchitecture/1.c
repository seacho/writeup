// ###
// ### Welcome to /challenge/babyArchParseOnePage!
// ###

// This challenge will inject a region of shared memory into the binary specified via argv[1].
// Please pass your executable's path as the first argument.


// This shared memory region will be accessible in your binary memory at address: 0x1337000.
// This means you can access shared_memory_base (in the code below) at 0x1337000 in your binary.You DO NOT need to call mmap.  Assume this memory is mapped in your code before main is even
// called.

// This challenge will perform a timing sidechannel attack against itself!
// It can access a single byte of the flag in the challenge's memory.
// However, the flag bytes are not accessible by your code!

// You can control which byte of the flag is read via the injected shared memory.
// This flag byte value will influence which page of memory is accessed as shown in the code
// below.

// This challenge will then measure memory access times at the beginning of each page
// and make this data available to you via shared memory.
// Use this information to determine which index is in the CPU cache!
// Hint: Cached memory addresses have noticeable faster access times. This information can be
// used as a sidechannel to reveal the flag byte's value.

// This challenge will execute the following code after launching your challenge binary.
// Note that the challenge binary will be blocked on sem_wait and unable to continue execution.
// You can influence the binary's behavior by calling sem_post on this semaphore from your code.
// ----------------
// Shared memory will start with a semaphore
// that allows hacker program to trigger behavior
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(){
    sem_t *sem = (sem_t *) 0x1337000;
    sem_init(sem, 1, 0);

    // Followed by a flag access index.
    int *index = (int *) (sem + 1);
    *index = 0;

    char *ptr;
    char buf;
    char leak;
    int status;
    puts("Waiting..");
    while (waitpid(exploit_pid, &status, WNOHANG) != exploit_pid) {
    sem_wait(sem);
    // Immediately after will be an index into the flag value
    int *index = (int *) (sem + 1);

    uint64_t timing_data[255];

    flush_cache();

    leak = flag_val[*index];
    ptr = shared_memory_base + 0x1000 + 0x1000 * (int) leak;
    buf = *ptr;

    get_timing_data(index, sem, timing_data);

    // Write the timing data to the second page of shared memory
    for (int i = 0; i < 256; i++) {
        uint64_t *page = (uint64_t *) (shared_memory_base + 0x1000)
        page[i] = timing_data[i]
    }
    }
}