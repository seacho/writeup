#include <mach/vm_map.h> 
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>

// 必须与发送端完全一致的结构体（4字节对齐）
typedef struct __attribute__((aligned(4))) {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t data_desc;
} OOLMessage;

typedef struct {
    mach_msg_header_t header;
    char data[0x1000];          // 内联消息数据
} CustomMessage;

// 创建并注册服务端口
mach_port_t setup_receive_port() {
    mach_port_t port;
    kern_return_t kr;

    // 1. 创建新端口
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("Port allocate failed: %s\n", mach_error_string(kr));
        return MACH_PORT_NULL;
    }

    // 2. 添加发送权限（允许其他进程发送消息）
    kr = mach_port_insert_right(
        mach_task_self(),
        port,
        port,
        MACH_MSG_TYPE_MAKE_SEND
    );
    if (kr != KERN_SUCCESS) {
        printf("Insert right failed: %s\n", mach_error_string(kr));
        mach_port_destroy(mach_task_self(), port);
        return MACH_PORT_NULL;
    }

    // 3. 注册到 bootstrap 服务（假设服务名为 "com.xxx"）
    kr = bootstrap_register(
        bootstrap_port,
        "college.pwn.mac-ports.challenge.9c",
        port
    );
    if (kr != KERN_SUCCESS) {
        printf("Register failed: %s\n", mach_error_string(kr));
        mach_port_destroy(mach_task_self(), port);
        return MACH_PORT_NULL;
    }

    return port;
}

// 主接收循环
void receive_loop(mach_port_t port) {
    OOLMessage msg;
    kern_return_t kr;

    while (1) {
        // 初始化消息结构
        memset(&msg, 0, sizeof(msg));

        // 接收消息（阻塞模式）
        kr = mach_msg(
            (mach_msg_header_t*)&msg,
            MACH_RCV_MSG | MACH_RCV_LARGE, // 允许接收大消息
            0,
            0x1000,
            port,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL
        );

        if (kr != KERN_SUCCESS) {
            printf("Receive error: %s\n", mach_error_string(kr));
            break; //如果接收失败会一直接收，一直失败
        }

        // 验证消息格式
        if (!(msg.header.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
            printf("Error: Not a complex message!\n");
            continue;
        }

        if (msg.body.msgh_descriptor_count != 1) {
            printf("Error: Descriptor count mismatch!\n");
            continue;
        }

        /* // 提取 OOL 数据 */
        void *data = msg.data_desc.address;
        mach_vm_size_t size = msg.data_desc.size;

        printf("Received OOL data: address=%p, size=%llu\n", data, size);

        // 使用数据
        if (data != NULL) {
            printf("Data preview:\n%s\n",(char *)data);
        }

        // 必须释放 OOL 内存！
        kr = vm_deallocate(
            mach_task_self(),
            (mach_vm_address_t)data,
            size
        );
        if (kr != KERN_SUCCESS) {
            printf("Deallocate failed: %s\n", mach_error_string(kr));
        }
        break;
    }
}

int main() {
    mach_port_t port = setup_receive_port();
    if (port == MACH_PORT_NULL) {
        return 1;
    }

    printf("Service running on port: %#x\n", port);
    receive_loop(port);

    // 清理（通常不会执行到这里）
    printf("destroy mach_port\n");
    mach_port_destroy(mach_task_self(), port);
    return 0;
}
