#ifndef __SYNC_H
#define __SYNC_H

#include "bpf.h"
#include "config.h"
#include "entry.h"
#include "error.h"

// Syncs eBPF map with entries.
error_t *sync_bpf(const bpf_handle *hnd, const config *cfg, entries *ies);

#endif
