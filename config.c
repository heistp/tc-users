#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "config.h"
#include "error.h"

#define RANGE_DELIM "-:"
#define CLASSIFY_BY_DELIM ","

// Classify addr strings.
static const char * const classify_addr_strs[MAX_CLASSIFY_ADDR-1] = {
	"srcmac",
	"dstmac",
	"srcip",
	"dstip",
};

static classify_addr parse_classify_addr(const char *s) {
	int i;

	for (i = 0; i < MAX_CLASSIFY_ADDR-1; i++) {
		if (!strcmp(s, classify_addr_strs[i])) {
			return i + 1;
		}
	}

	return -1;
}

static unsigned long floor_pow2(const unsigned long n)
{
    unsigned long p = 1;

    if (n && !(n & (n - 1)))
        return n;
    while (p <= n) {
        p <<= 1;
	}
	p >>= 1;

    return p;
}

static uint16_t calculate_fpu(const config *cfg, const unsigned long num_users)
{
	unsigned long u;
	uint16_t fpu;

	u = u16_range_size(&cfg->user_flows) / num_users;
	if (u <= cfg->fpu_range.lo) {
		fpu = cfg->fpu_range.lo;
	} else if (u >= cfg->fpu_range.hi) {
		fpu = cfg->fpu_range.hi;
	} else {
		u = floor_pow2(u);
		if (u > cfg->fpu_range.hi) {
			fpu = cfg->fpu_range.hi;
		} else {
			fpu = u;
		}
	}

	return fpu;
}

void init_config(config *cfg)
{
	*cfg = (const config) {
		RUN,
		{ D_USER_FLOW_LO, D_USER_FLOW_HI, },
		{ D_UNCL_FLOW_LO, D_UNCL_FLOW_HI, },
		{ D_FLOWS_PER_USER_LO, D_FLOWS_PER_USER_HI, },
		D_CLASSIFY_BY,
		false,
		LOG_NORMAL,
		NULL,
		0,
	};
}

error_t *parse_u16_range(const char *s, u16_range *r)
{
	char ts[MAX_RANGE_STRLEN+1];
	char *slo, *shi, *p;

	strncpy(ts, s, MAX_RANGE_STRLEN+1);
	if ((slo = strtok_r(ts, RANGE_DELIM, &p)) == NULL) {
		return error(E_EMPTY_RANGE);
	}
	if (parse_u16(slo, &r->lo)) {
		return errorf(E_INVALID_RANGE_VALUE, "%s", slo);
	}

	if ((shi = strtok_r(NULL, RANGE_DELIM, &p)) == NULL) {
		r->hi = r->lo;
		return NULL;
	}
	if (parse_u16(shi, &r->hi)) {
		return errorf(E_INVALID_RANGE_VALUE, "%s", shi);
	}

	if (strtok_r(NULL, RANGE_DELIM, &p)) {
		return errorf(E_INVALID_RANGE, "%s", s);
	}
	if (r->lo > r->hi) {
		return errorf(E_INVALID_RANGE, "%s", s);
	}

	return NULL;
}

bool u16_ranges_overlap(const u16_range *r1, const u16_range *r2)
{
	return !(r2->hi < r1->lo || r2->lo > r1->hi);
}

char *u16_range_str(const u16_range *r, char *s)
{
	snprintf(s, MAX_RANGE_STRLEN+1, "%u-%u", r->lo, r->hi);
	return s;
}

uint16_t u16_range_size(const u16_range *r)
{
	return r->hi - r->lo + 1;
}

bool is_in_range(const u16_range *r, const uint16_t v)
{
	return v >= r->lo && v <= r->hi;
}

error_t *parse_u16(const char *s, uint16_t *u)
{
	char *end;
	int i;

	i = strtol(s, &end, 10);
	if (!*s || i < 0 || i > UINT16_MAX || *end) {
		return errorf(E_INVALID_U16_VALUE, "%s", s);
	}
	*u = i;

	return NULL;
}

error_t *parse_classify_by(const char *s, classify_by cb)
{
	char ts[MAX_CLASSIFY_BY_STRLEN+1];
	bool empty = true;
	char *t, *p, *ss;
	classify_addr a;
	int i, j;

	strncpy(ts, s, MAX_CLASSIFY_BY_STRLEN+1);
	for (i = 0, ss = ts; i < MAX_CLASSIFY_BY_ADDRS; i++, ss = NULL) {
		if ((t = strtok_r(ss, CLASSIFY_BY_DELIM, &p)) == NULL) {
			cb[i] = 0;
		} else if ((a = parse_classify_addr(t)) == -1) {
			return errorf(E_INVALID_CLASSIFY_BY_ADDR, "%s", t);
		} else {
			for (j = i-1; j >= 0; j--) {
				if (cb[j] == a) {
					return errorf(E_INVALID_CLASSIFY_BY_REPEAT, "%s", s);
				}
			}
			cb[i] = a;
			empty = false;
		}
	}
	if (empty) {
		return errorf(E_INVALID_CLASSIFY_BY_OPTION, "%s", s);
	}
	if (strtok_r(NULL, CLASSIFY_BY_DELIM, &p)) {
		return errorf(E_INVALID_CLASSIFY_BY_TOO_LONG, "%s", s);
	}

	return NULL;
}

char *classify_by_str(const classify_by cb, char *s)
{
	const char *t;
	int i, r, l;

	s[0] = '\0';
	for (i = 0, r = MAX_CLASSIFY_BY_STRLEN+1; i < MAX_CLASSIFY_BY_ADDRS && r > 0; i++) {
		if (cb[i] == 0) {
			break;
		}
		if (i > 0) {
			strncat(s, ",", r--);
		}
		t = classify_addr_strs[cb[i]-1];
		l = strlen(t);
		strncat(s, t, r);
		r -= l;
	}

	return s;
}

bool is_u16_pow2(const uint16_t x)
{
	return x && !(x & (x - 1));
}

void copy_classify_by(classify_by dst, const classify_by src)
{
	int i;

	for (i = 0; i < MAX_CLASSIFY_BY_ADDRS; i++) {
		dst[i] = src[i];
	}
}

error_t *validate_config(const config *cfg)
{
	char rstr1[MAX_RANGE_STRLEN+1];
	char rstr2[MAX_RANGE_STRLEN+1];

	if (u16_ranges_overlap(&cfg->user_flows, &cfg->uncl_flows)) {
		return errorf(E_FLOW_RANGES_OVERLAP, "%s and %s",
			u16_range_str(&cfg->user_flows, rstr1),
			u16_range_str(&cfg->uncl_flows, rstr2));
	}

	if (cfg->fpu_range.lo < 1 || !is_u16_pow2(cfg->fpu_range.lo)) {
		return errorf(E_INVALID_MIN_FLOWS_PER_USER, "%u", cfg->fpu_range.lo);
	}
	if (cfg->fpu_range.hi < 1 || !is_u16_pow2(cfg->fpu_range.hi)) {
		return errorf(E_INVALID_MAX_FLOWS_PER_USER, "%u", cfg->fpu_range.hi);
	}

	if (u16_range_size(&cfg->user_flows) % cfg->fpu_range.lo != 0) {
		return errorf(E_USER_FLOWS_SIZE_NOT_MULTIPLE_MIN, "%u %% %u != 0",
			u16_range_size(&cfg->user_flows), cfg->fpu_range.lo);
	}
	if (u16_range_size(&cfg->user_flows) % cfg->fpu_range.hi != 0) {
		return errorf(E_USER_FLOWS_SIZE_NOT_MULTIPLE_MAX, "%u %% %u != 0",
			u16_range_size(&cfg->user_flows), cfg->fpu_range.hi);
	}

	if (!is_u16_pow2(u16_range_size(&cfg->uncl_flows))) {
		return errorf(E_UNCL_FLOWS_SIZE_NOT_POW2, "is %u",
			u16_range_size(&cfg->uncl_flows));
	}

	return NULL;
}

void finalize_config(config *cfg, const unsigned long num_users)
{
	cfg->flows_per_user = calculate_fpu(cfg, num_users);
}
