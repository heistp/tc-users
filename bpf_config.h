#ifndef __BPF_CONFIG_H
#define __BPF_CONFIG_H

#include "config.h"

#define BPF_CONFIG_KEY 1

typedef struct {
	classify_by classify_by;
	uint16_t flows_per_user;
	uint16_t uncl_flows_start;
	uint16_t uncl_flows_len;
} bpf_config;

// Initializes BPF config from tc-users config.
void init_bpf_config(const config *cfg, bpf_config *bcfg);

#endif
