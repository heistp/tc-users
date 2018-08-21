#ifndef __ENTRY_H
#define __ENTRY_H

#include <stdbool.h>

#include "addr.h"
#include "limits.h"

// Contains one mapping of address, user ID and class ID.
typedef struct {
	addr addr;
	char userid[MAX_USERID_STRLEN+1];
	uint16_t classid;
	bool classified;
} entry;

// Contains an array of entries.
typedef struct {
	entry *arr;
	unsigned long len;
	unsigned long cap;
} entries;

// An entries iterator.
typedef struct {
	entries *es;
	unsigned long pos;
} ents_it;

// Creates new entries.
entries *new_entries();

// Appends an entry.
void append_entry(entries *es, const entry *e);

// Sorts entries with a comparator.
void sort_entries(entries *es, int (*compar)(const void *, const void *));

// Frees an entries.
void free_entries(entries *es);

// Creates a new entries iterator.
ents_it *new_ents_it(entries *es);

// Returns the next entry in the iteration (NULL if no more).
entry *es_next(ents_it *it);

// Returns the next entry in the iteration (NULL is no more), and previous.
entry *es_next_prev(ents_it *it, entry **prev);

#endif
