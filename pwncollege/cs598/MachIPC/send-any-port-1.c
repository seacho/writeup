#include <mach/mach.h>
#include <mach/mach_port.h>
#include <bootstrap.h>  // for extern bootstrap_port
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    mach_msg_header_t header;
    char data[256];          // 内联消息数据
} CustomMessage;

int main()
{
    // 1. 查找名为xxx的端口
    const char * id = "college.pwn.mac-ports.cb";
    // mach_port_name_t name;
    mach_port_t remote_port = MACH_PORT_NULL;
    kern_return_t kr;
    
    kr = bootstrap_look_up(bootstrap_port, id, &remote_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to lookup port: %s\n", mach_error_string(kr));
        return -1;
    }
    //2. 构造消息
    CustomMessage msg = {0};
    mach_msg_header_t *header = &msg.header;

    // 设置消息头
    header->msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND);
    header->msgh_size = 0x20;
    header->msgh_remote_port = remote_port;  // 目标端口（com.xxx）
    header->msgh_local_port = MACH_PORT_NULL; // 不需要回复端口
    header->msgh_id = 0x1f;                   // 自定义消息ID

    strncpy(msg.data, "Hello from sender!", sizeof(msg.data));

    // 3. 发送消息
    kr = mach_msg(
        header,                   // 消息缓冲区
        MACH_SEND_MSG,            // 发送模式
        header->msgh_size,        // 消息大小
        0,                        // 接收缓冲区大小（不需要接收）
        MACH_PORT_NULL,           // 接收端口（不需要）
        MACH_MSG_TIMEOUT_NONE,    // 无超时
        MACH_PORT_NULL            // 通知端口（不需要）
    );

    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return -1;
    }

    // 4. 清理端口权限
    mach_port_deallocate(mach_task_self(), remote_port);
    return 0;
}
