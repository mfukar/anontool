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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include "anonymization.h"

extern int     *make_shift(char *ptrn, int plen);
extern int     *make_skip(char *ptrn, int plen);
extern int      mSearch(char *buf, int blen, char *ptrn, int plen, int *skip, int *shift);

struct strsearch_data {
	unsigned char	*str;
	int		slen;	/* length of string */
	int		offset;	/* Starting search position from the beginning of packet */
	int		depth;	/* Maximum search depth from the beginning of search position */
	int		*shift;	/* Boyer-Moore shift table */
	int		*skip;	/* Boyer-Moore skip table */
	char		not_flag;
};

short isEscaped(char *pos)
{
	int             num_of_slashes = 0;
	char           *tmp;

	tmp = pos - 1;
	while (*tmp == '\\') {
		tmp--;
		num_of_slashes++;
	}
	if (num_of_slashes % 2 == 0)
		return 0;
	return 1;
}

int strsearch_init(va_list vl, void *fu, struct anonflow *flow)
{
	struct function *f;
	struct strsearch_data *data;
	char           *tmps;
	int             tmp;
	unsigned char  *tmpstr, *tstrbak;
	unsigned char  *ret;	// holds the final parsed string
	int             len = 0;	// length of the final parsed string
	char            hexpair[3];
	unsigned char  *strbak;

	f = (struct function *)fu;
	data = (struct strsearch_data *)malloc(sizeof(struct strsearch_data));
	tmps = va_arg(vl, char *);
	data->str = (unsigned char *)strdup(tmps);	//str
	tmp = va_arg(vl, int);
	data->offset = tmp;	//offset
	tmp = va_arg(vl, int);
	data->depth = tmp;	//depth
	tmp = va_arg(vl, int);
	data->not_flag = tmp;	//not_flag

	if (strlen((char *)data->str) < 1 || data->offset < 0 || data->depth < 0)
		return 0;

	strbak = data->str;	// backup pointer
	tstrbak = tmpstr = malloc(strlen((char *)data->str) * sizeof(char));
	ret = tmpstr;
	hexpair[2] = '\0';

	while (*(data->str) != '\0') {
		// '|' means that hex mode begins unless it is escaped \|
		// every hex number consists of two characters ,e.g A is written as 0A
		if (*(data->str) == '|') {
			if (!isEscaped((char *)data->str)) {
				int             hexcount = 0;
				data->str++;
				//parse until closing '|'
				while (*(data->str) != '|') {
					if (*(data->str) == '\0') {
						return 0;
					}
					// |AC DE| => ignore white spaces between hex numbers
					if (*(data->str) == ' ') {
						data->str++;
						continue;
					}
					//convert hex to character
					hexpair[hexcount++] = *(data->str);
					if (hexcount == 2) {
						hexcount = 0;
						sscanf(hexpair, "%x", (int *)tmpstr);
						tmpstr++;
					}
					data->str++;
				}
			} else {
				*tmpstr = *(data->str);
				tmpstr++;
			}
		}
		// special case for escape character '\\'
		else if (*(data->str) == '\\') {
			if (isEscaped((char *)data->str)) {
				*tmpstr = *(data->str);
				tmpstr++;
			}
		} else {
			*tmpstr = *(data->str);
			tmpstr++;
		}
		data->str++;
	}
	len = tmpstr - ret;

	data->slen = len;
	data->str = malloc(len * sizeof(char));
	memcpy(data->str, ret, len);
	data->shift = make_shift((char *)ret, len);
	data->skip = make_skip((char *)ret, len);

	f->internal_data = data;

	return 1;
}

int strsearch_process(struct anonflow *flow, void *internal_data, unsigned char *dev_pkt,
		      anon_pkthdr_t * pkt_head)
{
	struct strsearch_data *data = (struct strsearch_data *)internal_data;
	unsigned char  *str;
	int             strlen;
	int             offset = data->offset;
	int             depth = data->depth;
	int             len = pkt_head->caplen - offset;
	int             result;

	str = data->str;
	strlen = data->slen;

	if (depth && (len > depth))
		len = depth;

	if (len < strlen) {
		result = 0;
	} else {
		if (mSearch
		    ((char *)(dev_pkt + offset), len, (char *)str, strlen, data->skip, data->shift))
			result = 1;
		else
			result = 0;
	}

	if (data->not_flag) {
		return !result;
	}

	return result;

}

struct finfo    strsearch_info = {
	"STRING_SEARCH",	//name
	"Searches for a pattern inside the packet",	//descr
	strsearch_init,		//init
	strsearch_process,	//process
};
