#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

char buf[0x1000];

int main(){
     
    int fds[0x40] = {0};
    for(int i = 0; i < 0x40;i++){
        fds[i] = open("/proc/self/stat",0);
    }
    getchar();
    for(int i = 0; i < 0x40;i++){
        read(fds[i], buf, 0x5);
    }
}