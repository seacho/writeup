#include <mach/mach.h>
#include <mach/mach_port.h>
#include <bootstrap.h>  // for extern bootstrap_port
#include <stdio.h>
#include <stdlib.h>

typedef struct __attribute__((aligned(4))) {
    mach_msg_header_t header;
    mach_msg_body_t body;                // 必须包含 body 字段
    mach_msg_ool_descriptor_t data_desc; // OOL 数据描述符
} OOLMessage;

int main()
{
    // 1. 查找名为xxx的端口
    const char * id = "college.pwn.mac-ports.61";
    // mach_port_name_t name;
    mach_port_t remote_port = MACH_PORT_NULL;
    kern_return_t kr;
    
    kr = bootstrap_look_up(bootstrap_port, id, &remote_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to lookup port: %s\n", mach_error_string(kr));
        return -1;
    }


    
    //2. 构造消息
    size_t data_size = 1024;
    void *data_buffer = malloc(data_size);
    memset(data_buffer, 0xAA, data_size); // 填充测试数据

    OOLMessage msg = {0};
    mach_msg_header_t *header = &msg.header;

    // 设置消息头
    header->msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX;
    header->msgh_size = sizeof(OOLMessage);
    header->msgh_remote_port = remote_port;
    header->msgh_local_port = MACH_PORT_NULL;
    header->msgh_id = 1001; // 自定义消息ID

    // Body 字段设置（必须指明描述符数量）
    msg.body.msgh_descriptor_count = 1; // 关键！表示包含1个OOL描述符

    // OOL 描述符设置
    msg.data_desc.address = data_buffer;
    msg.data_desc.size = data_size;
    msg.data_desc.copy = MACH_MSG_VIRTUAL_COPY; // 接收方会获得内存副本
    msg.data_desc.deallocate = FALSE; // 发送方不释放内存
    msg.data_desc.type = MACH_MSG_OOL_DESCRIPTOR;

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
