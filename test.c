#include <stdio.h>

int main(int argc, char* argv[])
{
    FILE e;
    FILE* pos = &e;
    printf("%p, %p", &pos->_file, &e._file);
    return 0;
}
