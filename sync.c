#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <linux/bpf.h>

#include "bpf.h"
#include "addr.h"
#include "sync.h"
#include "limits.h"
#include "log.h"

static int cmp_ents_by_addr(const void *p1, const void *p2)
{
	return cmp_addr(&((entry *) p1)->addr, &((entry *) p2)->addr);
}

static error_t *read_bpf_entries(const bpf_handle *hnd, entries *es)
{
	error_t *err;
	bpf_it *it;
	entry e;

	e = (const entry){{0}};
	it = bpf_new_it(hnd);
	while ((err = bpf_next(it, &e.addr, &e.classid)) == NULL && !it->done) {
		append_entry(es, &e);
	}

	free(it);
	return err;
}

error_t *sync_bpf(const bpf_handle *hnd, const config *cfg, entries *ies)
{
	entries *bes = new_entries();
	char astr[MAX_ADDR_STRLEN+1];
	ents_it *iit, *bit;
	entry *be, *ie;
	error_t *err;
	int c;

	if ((err = read_bpf_entries(hnd, bes))) {
		return err;
	}
	sort_entries(bes, cmp_ents_by_addr);

	sort_entries(ies, cmp_ents_by_addr);

	iit = new_ents_it(ies);
	bit = new_ents_it(bes);
	ie = es_next(iit);
	be = es_next(bit);

	while (ie || be) {
		if ((c = cmp_ents_by_addr(ie, be)) == 0) {
			if (ie->classid != be->classid) {
				logn(cfg, "Sync: update %s %u\n", addr_str(&ie->addr, astr), ie->classid);
				if (!cfg->noop &&
					(err = bpf_update(hnd, &ie->addr, ie->classid, BPF_EXIST))) {
					goto out;
				}
			} else {
				logv(cfg, "Sync: leave %s %u\n", addr_str(&ie->addr, astr), ie->classid);
			}
			ie = es_next(iit);
			be = es_next(bit);
		} else if (c < 0) {
			logn(cfg, "Sync: add %s %u\n", addr_str(&ie->addr, astr), ie->classid);
			if (!cfg->noop &&
				(err = bpf_update(hnd, &ie->addr, ie->classid, BPF_NOEXIST))) {
				goto out;
			}
			ie = es_next(iit);
		} else {
			logn(cfg, "Sync: delete %s %u\n", addr_str(&be->addr, astr), be->classid);
			if (!cfg->noop && (err = bpf_delete(hnd, &be->addr))) {
				goto out;
			}
			be = es_next(bit);
		}
	}

out:
	free(bit);
	free(iit);
	free_entries(bes);
	return err;
}
