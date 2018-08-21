#ifndef __CLASSIFY_H
#define __CLASSIFY_H

#include "bpf.h"
#include "config.h"
#include "entry.h"
#include "error.h"

// Assigns classids to entries.
void classify(const bpf_handle *hnd, const config *cfg, entries *es);

#endif
