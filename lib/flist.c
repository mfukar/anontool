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
#include <stdio.h>

#include "stdlib.h"
#include "flist.h"

/** \brief Append data to list
	\param list a pointer to a list
	\param data the data to place in the list
	\return 0 on success, or -1 on failure
*/
int flist_append(flist_t * list, int id, void *data)
{
	flist_node_t   *node;

	if ((node = malloc(sizeof(flist_node_t))) == NULL) {
		fprintf(stderr, "malloc failed for node in flist_append\n");
		return -1;
	}

	node->id = id;
	node->data = data;
	node->next = NULL;

	if (flist_head(list) == NULL)
		flist_head(list) = node;
	else
		flist_next(flist_tail(list)) = node;

	flist_tail(list) = node;
	list->size++;

	return 0;
}

int flist_insert_before(flist_t * list, flist_node_t * before, void *data)
{
	flist_node_t   *newnode, *node, *prev = NULL;

	if ((newnode = malloc(sizeof(flist_node_t))) == NULL)
		return -1;

	newnode->data = data;
	newnode->next = NULL;

	//Find before node
	node = flist_head(list);

	if (node == NULL) {
		flist_head(list) = newnode;
		flist_tail(list) = newnode;
	} else {
		while (node != NULL) {
			if (node != before) {
				prev = node;
				node = flist_next(node);
			} else
				break;
		}

		if (prev == NULL) {
			newnode->next = flist_head(list);
			flist_head(list) = newnode;
		} else {
			prev->next = newnode;
			newnode->next = node;
			if (node == NULL)
				flist_tail(list) = newnode;
		}
	}

	++flist_size(list);
	return 0;
}

/** \brief Prepend data to list
	\param list a pointer to list
	\param data the data to place in the list
	\return 0 on success, or -1 on failure
*/
int flist_prepend(flist_t * list, int id, void *data)
{
	flist_node_t   *node;

	if ((node = malloc(sizeof(flist_node_t))) == NULL)
		return -1;

	node->id = id;
	flist_data(node) = data;
	flist_next(node) = flist_head(list);

	flist_head(list) = node;
	if (flist_tail(list) == NULL)
		flist_tail(list) = node;

	list->size++;

	return 0;
}

/** \brief Pop the first element in the list
	\param list a pointer to a list
	\return a pointer to the element, or NULL if the list is empty
*/
void           *flist_pop_first(flist_t * list)
{
	void           *d;
	flist_node_t   *node;

	if (flist_head(list) == NULL)
		return NULL;

	d = flist_data((node = flist_head(list)));
	flist_head(list) = flist_next(node);
	free(node);
	if (--flist_size(list) == 0)
		flist_tail(list) = NULL;
	return d;
}

/** \ brief Initialize a single linked list
	\param list the list to initialize
*/
void flist_init(flist_t * list)
{
	flist_head(list) = flist_tail(list) = NULL;
	flist_size(list) = 0;
}

/** \brief Destroy and de-allocate the memory hold by a list
	\param list a pointer to an existing list
	\param dealloc flag that indicates whether stored data should also be de-allocated
*/
void flist_destroy(flist_t * list, flist_destroy_t dealloc)
{
	flist_node_t   *node;

	while ((node = flist_head(list))) {
		flist_head(list) = flist_next(node);
		if (dealloc == FLIST_FREE_DATA)
			free(flist_data(node));
		free(node);
	}
	flist_tail(list) = NULL;
	flist_size(list) = 0;
}

void           *flist_get(flist_t * list, int id)
{
	flist_node_t   *node = flist_head(list);

	while (node != NULL) {
		if (node->id == id)
			return node->data;
		else
			node = flist_next(node);
	}

	return NULL;
}

int flist_get_next_id(flist_t * list, int id)
{
	flist_node_t   *node = flist_head(list);

	while (node != NULL) {
		if (node->id == id) {
			node = flist_next(node);
			if (node == NULL)
				return 0;
			else
				return node->id;
		} else
			node = flist_next(node);
	}

	return 0;
}

void flist_move_before(flist_t * list, int before, int id)
{
	/*void *data= */ flist_remove(list, id, FLIST_LEAVE_DATA);
	//flist_insert_before(list,before,id,data);
}

void           *flist_remove(flist_t * list, int id, flist_destroy_t dealloc)
{
	flist_node_t   *node = flist_head(list);
	flist_node_t   *p = NULL;
	void           *data;

	while (node != NULL) {
		if (node->id == id) {
			--flist_size(list);
			data = node->data;
			if (p == NULL)
				flist_head(list) = node->next;
			else
				p->next = node->next;
			if (flist_tail(list) == node)
				flist_tail(list) = p;
			if (dealloc == FLIST_FREE_DATA)
				free(flist_data(node));
			free(node);
			return data;
		} else {
			p = node;
			node = flist_next(node);
		}
	}

	return NULL;
}

int flist_insert(flist_t * list, int id, void *data, int index)
{
	int             i;
	flist_node_t   *head = flist_head(list);
	flist_node_t   *prev = NULL;
	flist_node_t   *node;

	if (index == 0)
		return flist_prepend(list, id, data);
	if ((unsigned int)index >= flist_size(list))
		return flist_append(list, id, data);

	if ((node = malloc(sizeof(flist_node_t))) == NULL)
		return -1;

	node->id = id;
	node->data = data;

	for (i = 0; head != NULL; head = flist_next(head), i++) {
		if (i == index) {
			node->next = head;
			flist_next(prev) = node;
		}
		prev = head;
	}
	flist_size(list)++;

	return 0;
}

void flist_reverse(flist_t * list)
{
	flist_node_t   *node = NULL;
	flist_node_t   *prev = NULL;
	flist_node_t   *next = NULL;

	if (flist_head(list) == NULL)
		return;

	for (node = flist_head(list); node != NULL; node = next) {
		next = flist_next(node);
		flist_next(node) = prev;
		prev = node;
	}

	node = flist_head(list);
	flist_head(list) = flist_tail(list);
	flist_tail(list) = node;

	return;
}
