#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "bpf.h"
#include "classify.h"
#include "log.h"

typedef struct {
	uint16_t classid;
	uint16_t count;
} classid_count;

typedef struct {
	classid_count *arr;
	int base;
	int pos;
	int len;
} classid_hist;

static int cmp_ents(const void *p1, const void *p2)
{
	const entry *e1 = p1, *e2 = p2;
	int cld;

	if ((cld = e1->classified - e2->classified) == 0) {
		return strncmp(e1->userid, e2->userid, MAX_USERID_STRLEN+1);
	}

	return cld;
}

static int cmp_classid_count(const void *p1, const void *p2)
{
    const classid_count *c1 = p1, *c2 = p2;
	int cntd;

	if ((cntd = c1->count - c2->count) == 0) {
		return c1->classid - c2->classid;
	}

	return cntd;
}

static bool userid_to_classid(const config *cfg, const char *userid, uint16_t *classid)
{
	char *end;
	long uid;

	uid = strtol(userid, &end, 10);
	if (!*end && uid >= 0 && uid <= UINT16_MAX &&
		is_in_range(&cfg->user_flows, (uint16_t) uid)) {
		*classid = (uint16_t) uid;
		return true;
	}
	return false;
}

static classid_hist *new_classid_hist(const config *cfg, entries *es)
{
	ents_it *it = new_ents_it(es);
	classid_hist *cidh = NULL;
	entry *e;
	int i;

	cidh = malloc(sizeof(classid_hist));
	*cidh = (const classid_hist){0};
	cidh->base = cfg->user_flows.lo;
	cidh->len = u16_range_size(&cfg->user_flows);
	cidh->arr = malloc(cidh->len * sizeof(classid_count));
	for (i = 0; i < cidh->len; i++) {
		cidh->arr[i] = (const classid_count){0};
		cidh->arr[i].classid = cidh->base + i;
	}
	while ((e = es_next(it))) {
		if (e->classified) {
			cidh->arr[e->classid - cidh->base].count++;
		}
	}
	qsort(cidh->arr, cidh->len, sizeof(classid_count), cmp_classid_count);

	free(it);
	return cidh;
}

static uint16_t least_used_classid(classid_hist *h)
{
	classid_count *cnt;

	cnt = &h->arr[h->pos];
	h->pos++;
	if (h->pos >= h->len || h->arr[h->pos].count > cnt->count) {
		h->pos = 0;
	}
	cnt->count++;

	return cnt->classid;
}

static void free_classid_hist(classid_hist *h) {
	if (h) {
		free(h->arr);
	}
	free(h);
}

static void classify_direct(const bpf_handle *hnd, const config *cfg, entries *es)
{
	ents_it *it = new_ents_it(es);
	char astr[MAX_ADDR_STRLEN+1];
	entry *e;

	while ((e = es_next(it))) {
		if (!e->classified && (userid_to_classid(cfg, e->userid, &e->classid))) {
			e->classified = true;
			logv(cfg, "Classify: %s %u (direct from userid %s)\n",
				addr_str(&e->addr, astr), e->classid, e->userid);
		}
	}

	free(it);
}

static void classify_indirect(const bpf_handle *hnd, const config *cfg, entries *es)
{
	char astr[MAX_ADDR_STRLEN+1];
	classid_hist *cidh = NULL;
	ents_it *cit = NULL;
	entry *e, *pe;

	sort_entries(es, cmp_ents);
	if (es->len > 0 && !es->arr[0].classified) {
		cidh = new_classid_hist(cfg, es);
		cit = new_ents_it(es);
		while ((e = es_next_prev(cit, &pe))) {
			if (!e->classified) {
				if (pe && !strncmp(pe->userid, e->userid, MAX_USERID_STRLEN+1)) {
					e->classid = pe->classid;
					logv(cfg, "Classify: %s %u (existing for userid %s)\n",
						addr_str(&e->addr, astr), e->classid, e->userid);
				} else {
					e->classid = least_used_classid(cidh);
					logv(cfg, "Classify: %s %u (indirect for userid %s)\n",
						addr_str(&e->addr, astr), e->classid, e->userid);
				}
				e->classified = true;
			} else {
				break;
			}
		}
	}

	free(cit);
	free_classid_hist(cidh);
}

void classify(const bpf_handle *hnd, const config *cfg, entries *es)
{
	classify_direct(hnd, cfg, es);
	classify_indirect(hnd, cfg, es);
}
