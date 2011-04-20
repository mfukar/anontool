/*
 * @file        /home/mfukar/src/anontool/lib/util.h
 * @author      Michael Foukarakis
 * @version     1.0
 * @date
 *      Created:     Mon Jan 31, 2011 11:08 EET
 *      Last Update: Wed Apr 20, 2011 23:29 GTB Daylight Time
 *------------------------------------------------------------------------
 * Description: Header file for utility functions
 *------------------------------------------------------------------------
 * History:     Nothing yet
 * TODO:        Nothing yet
 *------------------------------------------------------------------------
 */

#ifndef ANONLIB_UTIL_H
#define ANONLIB_UTIL_H

/* Swap bytes in 64 bit value, changing endianness */
#define swap_bytes_64(x) \
    ((((x) & 0xff00000000000000ull) >> 56)   \
   | (((x) & 0x00ff000000000000ull) >> 40)   \
   | (((x) & 0x0000ff0000000000ull) >> 24)   \
   | (((x) & 0x000000ff00000000ull) >>  8)   \
   | (((x) & 0x00000000ff000000ull) <<  8)   \
   | (((x) & 0x0000000000ff0000ull) << 24)   \
   | (((x) & 0x000000000000ff00ull) << 40)   \
   | (((x) & 0x00000000000000ffull) << 56))

typedef enum {
        ANONLIB_LITTLE_ENDIAN,
        ANONLIB_BIG_ENDIAN
} anonlib_endian_t;

uint64_t ntohq(uint64_t);
uint64_t htonq(uint64_t);

#endif
