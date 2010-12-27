/*
 * anontool Copyright Notice, License & Disclaimer
 *
 * Copyright 2006 by Antonatos Spiros, Koukis Demetres & Foukarakis Michael
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both the
 * copyright notice and this permission notice and warranty disclaimer appear
 * in supporting documentation, and that the names of the authors not be used
 * in advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.
 *
 * The authors disclaim all warranties with regard to this software, including all
 * implied warranties of merchantability and fitness.  In no event shall we be liable
 * for any special, indirect or consequential damages or any damages whatsoever
 * resulting from loss of use, data or profits, whether in an action of contract,
 * negligence or other tortious action, arising out of or in connection with the
 * use or performance of this software.
 */
#include "anonymization.h"

/* Maps the field to an integer according to the map_table. If field 
hasn't been mapped yet the map table will be updated. Mapping is incremental
, for example first IP seen is mapped to 1,  second IP to 2 and the mapping
never changes. IP have separate mapping table from ports while all other 
fields share a common mapping table. The content of the field are replaced 
by the mapped value. */
void map_field(unsigned char *field, short len, mapNode **map_table,int *count);

/* The mapping tables will be accessed in a uniform way through a set of
 functions */
/* lookup a value in the table. As soon as the implementation beging void 
pointers will be replaced with pointer to internal data structures */
unsigned int lookup_value(mapNode **map_table, unsigned int value);
/* Insert a value to a mapping table */
void insert_value(mapNode **map_table, unsigned int value, unsigned int mapped_value);

/* Replaces the field with a value extracted from a distribution. Distribution 
type defines which distribution to be used: 0 for uniform and 1 for Gaussian. 
Median and standard_deviation are passed as parameters to the Gausian 
distribution. Min and max are passed as parameters to the uniform distribution*/
void map_distribution(unsigned char *field, short len, int distribution_type, int arg1, int arg2);

/*Gaussian deviation*/
float box_muller(float m, float s);

/* Strip function can only be applied to payload. Header fields cannot be removed. The header 
length reduces accordingly */
void strip (anonpacket *p, unsigned char *field, int len,int keep_bytes, int total_len, unsigned char* packet_end);
    
/*Fills a field with a pattern. Pattern can be integer or string. Pattern 
type declares the type of pattern , 0 for integers, 1 for strings. For
example, we can fill the TCP payload field with the constant string "ABCDEFGH"
, just like the way iperf tool does. The function will be invoked as 
pattern_fill_field(p->tcphdr->payload,1500,"ABCDEFGH",1) or if we want to 
zero the TLL field it will be called as pattern_fill_field(p->iphdr->ttl,1,0,0)*/
void pattern_fill_field(unsigned char *field, int len, int pattern_type, void *pattern); 

/* Replaces field with random numbers. S is used as a seed to the random
number generator */
void random_field(unsigned char *field, int len);

/* Replaces field until . with printable characters*/
void filename_random_field(unsigned char *p, int len);

/* The prototypes for the hashing functions. They all replace the field with a hashing value. 
If the length of the hashing value is smaller than the length of the field then padding behavior
indicates how the rest of the field will be treated: PAD_WITH_ZERO sets the rest of the field to 
zero and STRIP_REST adjust the field to the anonpacket p (total packet length is reduced).
The hashing functions fail and return -1 if the hashing value has length greater than the length
of the field they sunstitute. In all other cases they return 0. */ 
int md5_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
int crc32_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
int sha1_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);
int sha256_hash(unsigned char *field, int len, int padding_behavior, anonpacket *p, int total_len, unsigned char * packet_end,int donotreplace);

/*padding functions*/
void hash_padding(unsigned char *field, int len, int padding_behavior,unsigned char *pattern, int hash_length, anonpacket *p,int total_length, unsigned char * packet_end,int donotreplace);
    
/* The des_hash function encrypts the fields according to the DES algorithm with the key provided as a parameter*/
int des_hash(unsigned char *field, int len, unsigned char *key, int padding_behavior, anonpacket *p);
/* AES supports multiple key lengths (128, 192 and 256 bit) */
int aes_hash(unsigned char *field, int len, unsigned char *key, unsigned int keylen, int padding_behavior, anonpacket *p);

/* Replaces parts of the field that match the regular expression with string that are contained 
inside the replacement vector. Returns -1 if regular expression matching fails or replacement
vector is too small */
int reg_exp_substitute(unsigned char *field, int len, char *regular_expression, char **replacement_vector, int num_of_matches,anonpacket *p,int total_len,unsigned char *packet_end);

/* The value of field is replaced by the pattern. If the length of the pattern is greater or less than the length of the field the rest of the packet is shifted accordingly and the header length is adjusted to the new length. Returns -1 if the replacement exceeds the MTU size and 0 if replacement is successful */
int replace_field(unsigned char *field, int len, unsigned char * pattern, int pattern_len, anonpacket *p, int total_len, unsigned char *packet_end);

/*Checks if new packet length exceeds MTU*/
int checkMTU(int packet_length, int field_old_length, int field_new_length);
