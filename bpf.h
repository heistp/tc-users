#ifndef __BPF_H
#define __BPF_H

#include <stdbool.h>

#include "addr.h"
#include "bpf_config.h"
#include "error.h"

// BPF file descriptors.
typedef struct {
	int afds[MAX_ADDR_TYPE];
	int cfd;
} bpf_handle;

// BPF maps iterator.
typedef struct {
	const bpf_handle *hnd;
	addr_type addr_type;
	void *key;
	bool done;
} bpf_it;

// Opens the BPF maps.
error_t *bpf_open(bpf_handle *hnd);

// Closes the BPF maps.
error_t *bpf_close(const bpf_handle *hnd);

// Looks up a classid by address.
error_t *bpf_lookup(const bpf_handle *hnd, const addr *addr, uint16_t *classid, bool *found);

// Updates an address to classid mapping.
error_t *bpf_update(const bpf_handle *hnd, const addr *addr, const uint16_t classid,
	const uint64_t flags);

// Deletes an address to classid mapping.
error_t *bpf_delete(const bpf_handle *hnd, const addr *addr);

// Updates the BPF configuration.
error_t *bpf_update_config(const bpf_handle *hnd, const bpf_config *bcfg);

// Creates a new BPF maps iterator.
bpf_it *bpf_new_it(const bpf_handle *hnd);

// Returns the next entry in the iteration (it->done == true if no more).
error_t *bpf_next(bpf_it *it, addr *next, uint16_t *classid);

#endif
