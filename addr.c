#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "addr.h"

#define MAC_DELIM ":"
#define LAST_MAC_COLON_POS 14

static int const addr_type_sizes[MAX_ADDR_TYPE] = {
	MAC_LEN,
	IP4_LEN,
	IP6_LEN,
};

static addr_type detect_addr_type(const char *s)
{
	addr_type t = -1;
	int len;
	int i;

	len = strlen(s);
	if (len == MAC_STRLEN) {
		t = MAC;
	}
	for (i = 0; i < len; i++) {
		if (s[i] == '.') {
			t = IP4;
			break;
		}
		if (s[i] == ':') {
			if (t != MAC || i > LAST_MAC_COLON_POS || ((i - 2) % 3 != 0)) {
				t = IP6;
				break;
			}
		}
	}

	return t;
}

static error_t *parse_mac(const char *s, mac_addr mac)
{
	char ts[MAC_STRLEN+1];
	char *t, *p, *ss;
	int i, r;
	char x;

	if (strlen(s) != MAC_STRLEN) {
		return error(E_INVALID_MAC);
	}
	strncpy(ts, s, MAC_STRLEN+1);
	ss = ts;
	for (i = 0; i < MAC_LEN; i++, ss = NULL) {
		t = strtok_r(ss, MAC_DELIM, &p);
		r = sscanf(t, "%"SCNx8 "%c", &mac[i], &x);
		if (r != 1) {
			return error(E_INVALID_MAC);
		}
	}
	if (strtok_r(NULL, MAC_DELIM, &p)) {
		return error(E_INVALID_MAC);
	}

	return NULL;
}

static void mac_str(const mac_addr mac, char *s)
{
	snprintf(s, MAC_STRLEN+1, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static error_t *parse_ip4(const char *s, ip4_addr ip4)
{
	if (inet_pton(AF_INET, s, ip4) == 0) {
		return errorf(E_INVALID_IP4_ADDR, "%s", s);
	}

	return NULL;
}

static error_t *ip4_str(const ip4_addr ip4, char *s)
{
	if (inet_ntop(AF_INET, ip4, s, MAX_ADDR_STRLEN+1) == NULL) {
		return errorf(E_IP4_STR_ERROR, "%s", strerror(errno));
	}

	return NULL;
}

static error_t *parse_ip6(const char *s, ip6_addr ip6)
{
	if (inet_pton(AF_INET6, s, ip6) == 0) {
		return errorf(E_INVALID_IP6_ADDR, "%s", s);
	}

	return NULL;
}

static error_t *ip6_str(const ip6_addr ip6, char *s)
{
	if (inet_ntop(AF_INET6, ip6, s, MAX_ADDR_STRLEN+1) == NULL) {
		return errorf(E_IP6_STR_ERROR, "%s", strerror(errno));
	}

	return NULL;
}

error_t *parse_addr(const char *s, addr *a)
{
	if ((a->type = detect_addr_type(s)) == -1) {
		return errorf(E_UNKNOWN_ADDR_FORMAT, "%s", s);
	}

	switch (a->type) {
	case MAC:
		return parse_mac(s, a->val.mac);
	case IP4:
		return parse_ip4(s, a->val.ip4);
	case IP6:
		return parse_ip6(s, a->val.ip6);
	default:
		return errorf(E_UNKNOWN_ADDR_TYPE, "%d", a->type);
	}
}

char *addr_str(const addr *a, char *s)
{
	error_t *err;
	
	switch (a->type) {
	case MAC:
		mac_str(a->val.mac, s);
		break;
	case IP4:
		if ((err = ip4_str(a->val.ip4, s))) {
			strncpy(s, err->message, MAX_ERROR_STRLEN+1);
		}
		break;
	case IP6:
		if ((err = ip6_str(a->val.ip6, s))) {
			strncpy(s, err->message, MAX_ERROR_STRLEN+1);
		}
		break;
	default:
		err = errorf(E_UNKNOWN_ADDR_TYPE, "%d", a->type);
		strncpy(s, err->message, MAX_ERROR_STRLEN+1);
		break;
	}

	return s;
}

int cmp_addr(const addr *a1, const addr *a2)
{
	int td;

	if (a1 == NULL) {
		if (a2 == NULL) {
			return 0;
		}
		return 1;
	} else if (a2 == NULL) {
		return -1;
	}

	if ((td = a1->type - a2->type) != 0) {
		return td;
	}

	return memcmp(&a1->val, &a2->val, addr_type_sizes[a1->type]);
}
