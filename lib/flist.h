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
#ifndef _FLIST_H
#define _FLIST_H 1

/*
 * Implementation of a single-linked list.
 */

typedef struct flist_node {
        int     id;
        void   *data;
        struct flist_node *next;
} flist_node_t;

typedef struct flist {
        flist_node_t *head;
        flist_node_t *tail;
        unsigned      size;
} flist_t;

//! Macro to get the head node of a list
#define flist_head(l) (l)->head
//! Macro to get the tail node of a list
#define flist_tail(l) (l)->tail
//! Macro to get the size of a list
#define flist_size(l) (l)->size
//! Macro to get the next node of a list
#define flist_next(n) (n)->next
//! Macro to get the data of a node
#define flist_data(n) (n)->data
#define flist_id(n) (n)->id

typedef enum {
        FLIST_LEAVE_DATA = 0,
        FLIST_FREE_DATA
} flist_destroy_t;

void flist_init(flist_t *);
void flist_destroy(flist_t *,flist_destroy_t);
void* flist_remove(flist_t *,int,flist_destroy_t);
int  flist_insert(flist_t *, int id, void*, int index);
void flist_reverse(flist_t*);
void flist_move_before(flist_t *,int before,int id);
extern inline void *flist_pop_first(flist_t *);
extern inline int flist_append(flist_t *,int id,void *);
extern inline int flist_insert_before(flist_t *,flist_node_t *before,void *);
extern inline int flist_prepend(flist_t *,int id,void *);
extern inline void* flist_get(flist_t *,int id);
extern inline int flist_get_next_id(flist_t *,int id);

#endif
