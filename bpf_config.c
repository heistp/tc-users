#include "bpf_config.h"

void init_bpf_config(const config *cfg, bpf_config *bcfg)
{
	*bcfg = (const bpf_config){{0}};
	copy_classify_by(bcfg->classify_by, cfg->classify_by);
	bcfg->flows_per_user = cfg->flows_per_user;
	bcfg->uncl_flows_start = cfg->uncl_flows.lo;
	bcfg->uncl_flows_len = u16_range_size(&cfg->uncl_flows);
}
