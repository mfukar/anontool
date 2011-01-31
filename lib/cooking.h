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
#ifndef _COOK_H_
#define _COOK_H_

#include "protocols.h"
#include "anonymization.h"

/* Session states */
#define SSN_TWH		0
#define SSN_ESTB	1
#define SSN_CLOSING	2
#define SSN_SCLOSED	3
#define SSN_CCLOSED	4
#define SSN_BCLOSED	5

struct cooking_data
{
	int threshold;
	int timeout;
	int id;
};

void		create_mod_pkt(unsigned char *, struct anonflow *, anon_pkthdr_t *);
#endif	//_COOK_H_
