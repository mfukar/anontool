/*
 * @file        /home/mfukar/src/anontool/lib/util.c
 * @author      Michael Foukarakis
 * @version     1.0
 * @date
 *      Created:     Mon Jan 31, 2011 10:45 EET
 *      Last Update: Wed Apr 20, 2011 21:33 GTB Daylight Time
 *------------------------------------------------------------------------
 * Description: Utility functions for anontool
 *------------------------------------------------------------------------
 * History:     Nothing yet
 * TODO:        Nothing yet
 *------------------------------------------------------------------------
 */
#include <stdint.h>
#include "util.h"

static inline anonlib_endian_t  find_endianness(void)
{
        union {
                unsigned int i;
                char c[sizeof(unsigned int)];
        } u;
        u.i = 0x01;
        if(u.c[0] == 0x01) {
                return ANONLIB_LITTLE_ENDIAN;
        } else {
                return ANONLIB_BIG_ENDIAN;
        }
}

uint64_t ntohq(uint64_t value)
{
        anonlib_endian_t endianness = find_endianness();

        if(endianness == ANONLIB_BIG_ENDIAN) {
                return value;
        }
        return swap_bytes_64(value);
}

uint64_t htonq(uint64_t value)
{
        anonlib_endian_t endianness = find_endianness();

        if(endianness == ANONLIB_BIG_ENDIAN) {
                return value;
        }
        return swap_bytes_64(value);
}
