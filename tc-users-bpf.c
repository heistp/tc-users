#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <iproute2/bpf_elf.h>

#include "bpf_config.h"

//#define DEBUG 1

#define DEFAULT_CLASS 1
#define MAX_ELEM 65536*4
#define IP4_ALEN 4
#define IP6_ALEN 16

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifdef DEBUG
#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
#endif

enum cstat {
	NOMATCH,
	MATCH,
	DONE,
};

struct hdrs {
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct iphdr *ip4;
};

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map tc_users_mac SEC(ELF_SECTION_MAPS) = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = ETH_ALEN,
    .size_value     = sizeof(uint16_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_ELEM,
    .flags          = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map tc_users_ip4 SEC(ELF_SECTION_MAPS) = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = IP4_ALEN,
    .size_value     = sizeof(uint16_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_ELEM,
    .flags          = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map tc_users_ip6 SEC(ELF_SECTION_MAPS) = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = IP6_ALEN,
    .size_value     = sizeof(uint16_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = MAX_ELEM,
    .flags          = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map tc_users_config SEC(ELF_SECTION_MAPS) = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(uint8_t),
    .size_value     = sizeof(bpf_config),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1,
};

__attribute__((always_inline))
inline enum cstat classify_mac(const unsigned char mac[ETH_ALEN], uint16_t *classid) {
	uint16_t *match;

	if ((match = map_lookup_elem(&tc_users_mac, mac)) == NULL) {
		return NOMATCH;
	}

	*classid = *match;
	return MATCH;
}

__attribute__((always_inline))
inline enum cstat classify_ip4(const void *ip4addr, uint16_t *classid) {
	uint16_t *match;

	if ((match = map_lookup_elem(&tc_users_ip4, ip4addr)) == NULL) {
		return NOMATCH;
	}

	*classid = *match;
	return MATCH;
}

__attribute__((always_inline))
inline enum cstat classify_ip6(const void *ip6addr, uint16_t *classid) {
	uint16_t *match;

	if ((match = map_lookup_elem(&tc_users_ip6, ip6addr)) == NULL) {
		return NOMATCH;
	}

	*classid = *match;
	return MATCH;
}

__attribute__((always_inline))
inline enum cstat classify_by_addr(const classify_addr caddr, const struct hdrs *h,
	uint16_t *classid)
{
	enum cstat cs = NOMATCH;

	switch (caddr) {
	case CLASSIFY_ADDR_NONE:
		cs = DONE;
		break;
	case SRC_MAC:
		if (h->eth) {
			cs = classify_mac(h->eth->h_source, classid);
		}
		break;
	case DST_MAC:
		if (h->eth) {
			cs = classify_mac(h->eth->h_dest, classid);
		}
		break;
	case SRC_IP:
		if (h->ip4) {
			cs = classify_ip4(&h->ip4->saddr, classid);
		} else if (h->ip6) {
			//memcpy(ip6addr, &h->ip6->saddr.in6_u.u6_addr8, IP6_ALEN);
			//cs = classify_ip6(&ip6addr, classid);
			//cs = classify_ip6(&h->ip6->saddr, classid);
		}
		break;
	case DST_IP:
		if (h->ip4) {
			cs = classify_ip4(&h->ip4->daddr, classid);
		} else if (h->ip6) {
			//memcpy(ip6addr, &h->ip6->daddr.in6_u.u6_addr8, IP6_ALEN);
			//cs = classify_ip6(&h->ip6->daddr, classid);
		}
		break;
	default:
		break;
	}

	return cs;
}

__attribute__((always_inline))
inline enum cstat classify(const classify_by clby, const struct hdrs *h,
	uint16_t *classid)
{
	enum cstat cstat;

	if ((cstat = classify_by_addr(clby[0], h, classid))) {
		return cstat;
	}
	if ((cstat = classify_by_addr(clby[1], h, classid))) {
		return cstat;
	}
	if ((cstat = classify_by_addr(clby[2], h, classid))) {
		return cstat;
	}
	if ((cstat = classify_by_addr(clby[3], h, classid))) {
		return cstat;
	}

	return NOMATCH;
}

__attribute__((always_inline))
void find_headers(const struct __sk_buff *skb, struct hdrs *h) {
	unsigned char *head, *tail;
	struct iphdr *ip4;
	uint16_t et;

	head = (void *)(unsigned long)skb->data;
	tail = (void *)(unsigned long)skb->data_end;
	if (head + sizeof(struct ethhdr) > tail) {
		return;
	}
	h->eth = (struct ethhdr *)head;
	head += sizeof(struct ethhdr);

	et = __be16_to_cpu(h->eth->h_proto);
	if (et == ETH_P_IP) {
		if (head + sizeof(struct iphdr) > tail) {
			return;
		}
		ip4 = (void *)head;
		if (head + ip4->ihl * 4 > tail) {
			return;
		}
		h->ip4 = ip4;
	} else if (et == ETH_P_IPV6) {
		if (head + sizeof(struct ipv6hdr) > tail) {
			return;
		}
		h->ip6 = (void *)head;
	}
}

SEC(ELF_SECTION_ACTION)
int act_main(struct __sk_buff *skb)
{
	struct hdrs h = (const struct hdrs){0};
	uint8_t ck = BPF_CONFIG_KEY;
	enum cstat cstat = NOMATCH;
	uint16_t classid;
	bpf_config *cfg;

	if ((cfg = map_lookup_elem(&tc_users_config, &ck)) == NULL) {
		goto out;
	}

	find_headers(skb, &h);

	cstat = classify(cfg->classify_by, &h, &classid);

out:

	if (cstat == MATCH) {
#ifdef DEBUG
		printk("class: %u\n", classid);
#endif
		skb->tc_classid = TC_H_MAKE(TC_H_ROOT, classid);
	}

	return TC_ACT_OK;
}

char __license[] SEC(ELF_SECTION_LICENSE) = "GPL";
