/*
 * @file        /home/mfukar/src/anontool/lib/sha512.h
 * @author      Michael Foukarakis
 * @version     0.5
 * @date
 *      Created:     Mon Feb 14, 2011 09:41 EET
 *      Last Update: Wed Feb 16, 2011 08:56 EET
 *------------------------------------------------------------------------
 * Description: SHA512 implementation headers for anontool
 *
 * http://csrc.nist.gov/publications/fips/fips180-3/fips180-3.pdf
 *------------------------------------------------------------------------
 * History:     None yet
 * TODO:        Much
 *------------------------------------------------------------------------
 */
#ifndef ANONTOOL_SHA2_H
#define ANONTOOL_SHA2_H

#define UL64(x) x##ULL

typedef enum {
        ANONTOOL_SHA2_BLOCK_384 = 384,
        ANONTOOL_SHA2_BLOCK_512 = 512,
} sha2_block_e;

/*
 * SHA-2 context structure
 */
typedef struct {
        uint64_t                total[2];       /* number of bytes processed  */
        uint64_t                state[8];       /* intermediate digest state  */
        unsigned char           buffer[128];    /* data block being processed */

        unsigned char           ipad[128];      /* HMAC: inner padding        */
        unsigned char           opad[128];      /* HMAC: outer padding        */
        sha2_block_e            block_size;     /* SHA-384 or SHA-512 */
} SHA2_context;

/*
 * SHA-2 context setup
 *
 * Parameters:
 * ctx          context to be initialized
 * block_size   SHA-2 block size
 *
 * Returns:     Nothing
 */
static void     SHA2_start(SHA2_context *, sha2_block_e block_size);

/*
 * SHA-2 process buffer
 *
 * Parameters:
 * ctx          SHA-2 context
 * input        buffer holding the data
 * ilen         length of the input data
 *
 * Returns:     Nothing
 */
static void     SHA2_update(SHA2_context *ctx, const unsigned char *input, int ilen);

/*
 * SHA-2 final digest
 *
 * Parameters:
 * ctx          SHA-2 context
 * digest       Buffer to place the digest
 *
 * Returns:     Nothing
 */
static void     SHA2_finish(SHA2_context *ctx, unsigned char digest[64]);

/*
 * Function to perform SHA-2 hashing that is exported to other translation units.
 *
 * Parameters:
 * input        buffer holding the  data
 * ilen         length of the input data
 * digest       Buffer to place the digest
 * block_size   SHA-384 or SHA-512
 */
void            SHA2(const unsigned char *input, int, unsigned char digest[64], sha2_block_e block_size);

/*
 * SHA-2 HMAC context setup
 *
 * Parameters:
 * ctx          HMAC context to be initialized
 * key          HMAC secret key
 * keylen       length of the HMAC key
 * block_size   SHA-384 or SHA-512
 *
 * Returns:     Nothing
 */
static void     SHA2_hmac_start(SHA2_context *ctx, const unsigned char *key, int keylen, sha2_block_e block_size);

/*
 * Update SHA-512 HMAC buffer
 *
 * Parameters:
 * ctx          HMAC context
 * input        buffer holding the  data
 * ilen         length of the input data
 *
 * Returns:     Nothing
 */
static void     SHA2_hmac_update(SHA2_context *ctx, const unsigned char *input, int ilen);

/*
 * Produces SHA-512 HMAC final digest
 *
 * Parameters:
 * ctx          HMAC context
 * digest       SHA-384/512 HMAC checksum result
 *
 * Returns:     Nothing
 */
static void     SHA2_hmac_finish(SHA2_context *ctx, unsigned char digest[64]);

/*
 * Reset SHA-512 HMAC context
 *
 * Parameters:
 * ctx          HMAC context to be reset
 *
 * Returns:     Nothing
 */
void            SHA2_hmac_reset(SHA2_context * ctx);

/*
 * Performs HMAC-SHA-512( key, buffer )
 *
 * Parameters:
 * key          HMAC secret key
 * keylen       length of the HMAC key
 * input        buffer holding the data
 * ilen         length of the input data
 * output       HMAC-SHA-384/512 digest
 * block_size   SHA-384 or SHA-512
 */
void            SHA2_hmac(const unsigned char *key,   int keylen,
                          const unsigned char *input, int ilen,
                                unsigned char  output[64], sha2_block_e block_size);

#endif
