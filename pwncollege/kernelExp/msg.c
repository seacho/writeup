#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
size_t target_cachesize = 128;
void ezblock() {
    puts("blocking!");
    char a;
    read(0, &a, 1);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        target_cachesize = strtoul(argv[1], NULL, 0);
    }
    size_t msgsz = target_cachesize - 0x30;
    char msgbuf[0x1000];
    memset(msgbuf, 0x1, 0x1000);
    int msqid[100];
    puts("\nBEFORE creating messages\n");
    ezblock();
    for (int i = 0; i < 20; i++) {
        int key = ftok(".", i);
        msqid[i] = msgget (key, 0666 | IPC_CREAT);
        msgsnd(msqid[i], msgbuf, msgsz, 0);
    }
    puts("\nAFTER creating messages\n");
    ezblock();
    for (int i = 0; i < 20; i++)
        msgrcv(msqid[i], msgbuf, msgsz, 0, 0);
    puts("\nAFTER FREEING messages\n" );
    ezblock();
    return 0;
}