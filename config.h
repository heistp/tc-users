#ifndef __CONFIG_H
#define __CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "error.h"

#define STRF(x) #x
#define STR(x) STRF(x)

#define MAX_RANGE_STRLEN 11
#define MAX_CLASSIFY_BY_STRLEN 25
#define MAX_CLASSIFY_BY_ADDRS 4

// defaults
#define D_USER_FLOW_LO 0
#define D_USER_FLOW_HI 895
#define D_UNCL_FLOW_LO 896
#define D_UNCL_FLOW_HI 1023
#define D_FLOWS_PER_USER_LO 1
#define D_FLOWS_PER_USER_HI 128
#define D_USER_FLOWS STR(D_USER_FLOW_LO) "-" STR(D_USER_FLOW_HI)
#define D_UNCL_FLOWS STR(D_UNCL_FLOW_LO) "-" STR(D_UNCL_FLOW_HI)
#define D_FLOWS_PER_USER STR(D_FLOWS_PER_USER_LO) "-" STR(D_FLOWS_PER_USER_HI)
#define D_CLASSIFY_BY { SRC_MAC, SRC_IP, 0, 0, }

// Log level.
typedef enum {
	LOG_QUIET = -1,
	LOG_NORMAL,
	LOG_VERBOSE,
} log_level;

// Classify by address.
typedef enum {
	CLASSIFY_ADDR_NONE,
	SRC_MAC,
	DST_MAC,
	SRC_IP,
	DST_IP,
	MAX_CLASSIFY_ADDR,
} classify_addr;

// Execution mode.
typedef enum {
	RUN,
	PRINT_HELP,
	PRINT_VERSION,
} run_mode;

// Range of uint16_t values.
typedef struct {
	uint16_t lo;
	uint16_t hi;
} u16_range;

// Classify by (four classify_addr values).
typedef classify_addr classify_by[MAX_CLASSIFY_BY_ADDRS];

// Configuration for tc-users.
typedef struct {
	run_mode mode;
	u16_range user_flows;
	u16_range uncl_flows;
	u16_range fpu_range;
	classify_by classify_by;
	bool noop;
	log_level log;
	char *input;
	uint16_t flows_per_user;
} config;

// Initializes config with default values.
void init_config(config *cfg);

// Parses range of uint16_t values.
error_t *parse_u16_range(const char *s, u16_range *r);

// Returns true if the specified u16 ranges overlap.
bool u16_ranges_overlap(const u16_range *r1, const u16_range *r2);

// Returns a string for a range (s should be sized MAX_RANGE_STRLEN+1).
char *u16_range_str(const u16_range *r, char *s);

// Returns the size of a u16_range.
uint16_t u16_range_size(const u16_range *r);

// Returns true if v is in range r.
bool is_in_range(const u16_range *r, const uint16_t v);

// Parses a uint16_t.
error_t *parse_u16(const char *s, uint16_t *u);

// Parses a classify_by string.
error_t *parse_classify_by(const char *s, classify_by cb);

// Returns a string for the classify_by value (s should be sized MAX_CLASSIFY_BY_STRLEN+1).
char *classify_by_str(const classify_by cb, char *s);

// Returns true if the specified uint16_t is power of 2.
bool is_u16_pow2(const uint16_t x);

// Copies a classify_by array.
void copy_classify_by(classify_by dst, const classify_by src);

// Validates the configuration.
error_t *validate_config(const config *cfg);

// Finalizes the configuration by calculating any computed parameters.
void finalize_config(config *cfg, const unsigned long num_users);

#endif
