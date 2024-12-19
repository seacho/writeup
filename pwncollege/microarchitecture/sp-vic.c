// gcc sp-vic.c -lrt -D_GNU_SOURCE -o sp-vic -lm
#define _GNU_SOURCE
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
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>
#define GUARDED_ARRAY_LENGTH 128

struct{
    char guarded_array[GUARDED_ARRAY_LENGTH];
    char secret_value[256];
}priv_struct;
char *shared_memory;

char *open_shared_mem(){
    int ret;
    int fd = shm_open("/shm_f", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    ret = ftruncate(fd, 0x1000 * 256);
    char *ptr = (char *)mmap(0, 255 * 0x1000, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    return ptr;
}



void set_affinity()
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    sched_setaffinity(0, sizeof(set), &set);

}

int main(int argc, char ** argv)
{
    volatile char buff[8];
    volatile int run, index, do_exit = 0;

    set_affinity();
    strcpy(priv_struct.guarded_array, "Here is my guarded value.");
    strcpy(priv_struct.secret_value, "pwned");

    shared_memory = open_shared_mem();

    ((volatile int *) shared_memory)[0] = 0;
    ((volatile int *) shared_memory)[1] = 0;
    ((volatile int *) shared_memory)[2] = 0;
    while(!do_exit){
        run = ((volatile int *) shared_memory)[0];

        while(!run){
            run = ((volatile int *) shared_memory)[0];
            do_exit = ((volatile int *) shared_memory)[2];
            sched_yield();
        }
        run = 0;
        index = 0;
        index = ((volatile int *) shared_memory)[1];

        volatile double tmp = (volatile double) ((int)(sqrtf(index * index)* 2/2));

        if (tmp < 128){
            buff[0] = shared_memory[priv_struct.guarded_array[index] * 0x1000];
        }
    }
    printf("exiting!\n");
}