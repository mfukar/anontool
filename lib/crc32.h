#ifndef _ANONTOOL_CRC_32
#define _ANONTOOL_CRC_32

/* Generate the CRC table. Must be called before calculating any CRC value. */
void gen_table(void);
unsigned long get_crc(unsigned char*, int);
#endif
