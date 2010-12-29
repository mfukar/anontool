#include "crc32.h"

static unsigned long crc_table[256];

void gen_table(void)
{
	unsigned long   crc, poly;
	int             i, j;

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--) {
			if (crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc >>= 1;
		}
		crc_table[i] = crc;
	}
}

unsigned long get_crc(unsigned char *p, int len)
{
	register unsigned long crc;
	int             ch, i;

	crc = 0xFFFFFFFF;
	for (i = 0; i < len; i++) {
		ch = p[i];
		crc = (crc >> 8) ^ crc_table[(crc ^ ch) & 0xFF];
	}

	return (crc ^ 0xFFFFFFFF);
}
