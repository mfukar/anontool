#ifndef _SHA1_H
#define _SHA1_H

/* Needed for memcpy() */
#include <string.h>
/* Needed for exact width types */
#include <stdint.h>

typedef struct
{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
}
sha1_context;

void sha1_starts( sha1_context *ctx );
void sha1_update( sha1_context *ctx, uint8_t *input, uint32_t length );
void sha1_finish( sha1_context *ctx, uint8_t digest[20] );
void sha1_process( sha1_context *ctx, uint8_t data[64] );
#endif /* sha1.h */
