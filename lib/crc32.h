#ifndef _PRINTF_H          /* defined in stdio.h */
#include <stdio.h>
#endif

/* generate the crc table. Must be called before calculating the crc value */
void gen_table(void);
unsigned long get_crc(unsigned char*, int);   /* calculate the crc32 value */
