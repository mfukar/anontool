#ifndef _DES_H
#define _DES_H

#include <stdint.h>

typedef struct
{
    uint32_t esk[32];     /* DES encryption subkeys */
    uint32_t dsk[32];     /* DES decryption subkeys */
}
des_context;

typedef struct
{
    uint32_t esk[96];     /* Triple-DES encryption subkeys */
    uint32_t dsk[96];     /* Triple-DES decryption subkeys */
}
des3_context;

int  des_set_key( des_context *ctx, uint8_t key[8] );
void des_encrypt( des_context *ctx, uint8_t input[8], uint8_t output[8] );
void des_decrypt( des_context *ctx, uint8_t input[8], uint8_t output[8] );

int  des3_set_2keys( des3_context *ctx, uint8_t key1[8], uint8_t key2[8] );
int  des3_set_3keys( des3_context *ctx, uint8_t key1[8], uint8_t key2[8],
                                        uint8_t key3[8] );

void des3_encrypt( des3_context *ctx, uint8_t input[8], uint8_t output[8] );
void des3_decrypt( des3_context *ctx, uint8_t input[8], uint8_t output[8] );

int des_main_ks( uint32_t SK[32], uint8_t key[8] );
void des_crypt( uint32_t SK[32], uint8_t input[8], uint8_t output[8] );
void des3_crypt( uint32_t SK[96], uint8_t input[8], uint8_t output[8] );

#endif /* des.h */
