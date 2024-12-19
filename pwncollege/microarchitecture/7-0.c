#include <stdint.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <stdio.h>
uint64_t measure(void *ptr)
{
    uint64_t start, end;
    start = _rdtsc();
    _mm_lfence();
    _mm_prefetch(ptr, 1);
    //__builtin_prefetch(ptr, 0, 1);
    _mm_lfence();
    end = _rdtsc();
    return end - start;
}

uint64_t repeat_measure(void *ptr)
{
    uint64_t sum = 0;

    for (int i = 0; i < 10; i++)
    {
        sum += measure(ptr);
    }
    return sum;
}

int main()
{
    char *ptr = (char *)mmap(NULL, 0x1000, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *(int *)ptr = 0x1337;
    printf("mmap returned: %p\n", ptr);
    for (char* i = ptr - (10 * 0x1000); i < ptr + (10 * 0x1000); i += 0x1000)
    {
        printf("addr: %p measurement: %lld\n", i, repeat_measure(i));
    }

    char buf[20]; 
    scanf ("%s", buf);
}