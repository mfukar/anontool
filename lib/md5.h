#ifndef _MD5_H
#define _MD5_H

/* Needed for memcpy() */
#include <string.h>
/* Needed for exact width types */
#include <stdint.h>

typedef struct
{
    uint32_t total[2];
    uint32_t state[4];
    uint8_t buffer[64];
}
md5_context;

void md5_sum(unsigned char *, uint32_t, unsigned char digest[16]);
#endif /* md5.h */
