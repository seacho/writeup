#include <x86intrin.h>
#include <stdio.h>
//_rdtsc <- Super high precision counter
//
// Fence ???
// lfence - blocks until all "Loads"are done
// sfence - blocks until all "stores" are done
// mfence - blocks until "both" have done
// clflush - refresh flush
char mem[0x1000 * 10];
unsigned long long start[10], finish[10];
char i_dont_care;
int main()
{
    // I want to do?
    // timestamp before
    // access somewhere in mem
    // timestamp after
    i_dont_care = mem[9*0x1000];
    for (int i = 0; i < 10; i++)
    {
        start[i] = _rdtsc();
        //_mm_mfence();
        i_dont_care = mem[i*0x1000];
        //_mm_mfence();
        finish[i] = _rdtsc();
        printf("index: %d\ttime: %llu\n", i, finish[i] - start[i]);
    }
    return 0;
}