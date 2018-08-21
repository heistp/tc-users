#ifndef __ADDR_H
#define __ADDR_H

#include <inttypes.h>

#include "error.h"

#define MAC_LEN 6
#define MAC_STRLEN 17
#define MAX_ADDR_STRLEN MAX_ERROR_STRLEN
#define IP4_LEN 4
#define IP6_LEN 16

// MAC address.
typedef uint8_t mac_addr[MAC_LEN];

// IPv4 address
typedef uint8_t ip4_addr[IP4_LEN];

// IPv6 address
typedef uint8_t ip6_addr[IP6_LEN];

// Address type.
typedef enum {
	MAC,
	IP4,
	IP6,
	MAX_ADDR_TYPE,
} addr_type;

// Address value.
typedef union {
	mac_addr mac;
	ip4_addr ip4;
	ip6_addr ip6;
} addr_val;

// Address of any supported type.
typedef struct {
	addr_type type;
	addr_val val;
} addr;

// Parses an address and determines its type.
error_t *parse_addr(const char *s, addr *a);

// Gets a string for an address. s should be sized MAX_ADDR_STRLEN+1.
char *addr_str(const addr *a, char *s);

// Compares two addresses.
int cmp_addr(const addr *a1, const addr *a2);

#endif
