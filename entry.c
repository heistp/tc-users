#include <stdlib.h>

#include "entry.h"

entries *new_entries()
{
	entries *es = malloc(sizeof(entries));
	*es = (const entries){0};
	return es;
}

void append_entry(entries *es, const entry *e)
{
	if (es->len == es->cap) {
		es->cap = (es->cap ? es->cap*2 : INITCAP_ENTRIES);
		es->arr = realloc(es->arr, es->cap * sizeof(entry));
	}
	es->arr[es->len] = *e;
	es->len++;
}

void sort_entries(entries *es, int (*compar)(const void *, const void *))
{
	qsort(es->arr, es->len, sizeof(entry), compar);
}

void free_entries(entries *es)
{
	if (es) {
		free(es->arr);
	}
	free(es);
}

ents_it *new_ents_it(entries *es)
{
	ents_it *it = malloc(sizeof(ents_it));
	*it = (const ents_it){0};
	it->es = es;
	return it;
}

entry *es_next(ents_it *it)
{
	entries *es = it->es;
	entry *e;

	if (it->pos >= es->len) {
		e = NULL;
		it->pos++;
	} else {
		e = &es->arr[it->pos++];
	}

	return e;
}

entry *es_next_prev(ents_it *it, entry **prev)
{
	entry *e = es_next(it);
	entries *es = it->es;

	*prev = (it->pos <= 1 ? NULL : &es->arr[it->pos-2]);

	return e;
}
