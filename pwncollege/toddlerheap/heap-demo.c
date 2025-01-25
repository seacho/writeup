// #include <stdio.h>
// #include <stdlib.h>
// #include <assert.h>
// #include <fcntl.h>
// #include <unistd.h>

// typedef struct _slot_t{
//     void *ptr;
//     int status;
// }slot_t;

// slot_t slots[1000];

// void meau()
// {
//     puts("1 - malloc");
//     puts("2 - free");
//     puts("3 - read");
//     puts("4 - print addr value");
//     puts("5 - free addr");
// }

// void do_action(int option)
// {
//     int idx = 0;
//     int size = 0;
//     unsigned long long addr = 0;
//     switch (option)
//     {
//     case 1:
//         puts("input index");
//         scanf("%d", &idx);
//         if(slots[idx].status != 0)
//         {
//             puts("maybe memory leak...");
//             break;
//         }
//         puts("input malloc_size");
//         scanf("%d", &size);
//         slots[idx].ptr = malloc(size);
//         printf("addr = %p\n", slots[idx].ptr);
//         slots[idx].status = 1;
//         break;

//     case 2:
//         puts("input index");
//         scanf("%d", &idx);
//         if(slots[idx].status == 0)
//         {
//             puts("maybe double free but do free...");
//         }
//         free(slots[idx].ptr);
//         slots[idx].status = 0;
//         break;

//     case 3:
//         puts("input target addr...");
//         scanf("%llx", &addr);
//         puts("input len...");
//         scanf("%d", &size);
//         read(0, (void*)addr, size);
//         break;

//     case 4:
//         puts("input target addr...");
//         scanf("%llx", &addr);
//         puts("input len...");
//         scanf("%d", &size);
//         for(int i= 0; i < size; i++)
//             printf("*%p = 0x%llx\n", (unsigned long long*)addr + i, *((unsigned long long*)addr + i));
//         break;

//     case 5:
//         puts("input target addr...");
//         scanf("%llx", &addr);
//         free((void*)addr);
//         break;
//     default:
//         break;
//     }
// }


// int main()
// {
//     int option;
//     while(1){
//         meau();
//         scanf("%d", &option);
//         do_action(option);
//     }

//     return 0;
// }

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
    void *alloc_slots[100];
    char command[128];
    int size;
    int index;
    while(1)
    {
        printf("malloc / free: \n");
        scanf("%s", command);
        if(strstr(command, "malloc")){
            scanf("%d", &index);
            scanf("%d", &size);
            alloc_slots[index] = malloc(size);
            printf("slots[%d] = malloc(%d) = %p", index, size, alloc_slots[index]);
        }else if(strstr(command, "free")){
            scanf("%d", &index);
            free(alloc_slots[index]);
            printf("free(slots[%d] = %p)",index, alloc_slots[index]);
        }else{
            assert("error command");
        }
    }
    return 0;
}

