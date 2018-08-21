#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <linux/bpf.h>

#include "bpf.h"
#include "bpf_config.h"
#include "bpflib.h"
#include "error.h"

#define BPF_MAPS_BASE "/sys/fs/bpf/tc/globals/tc_users_"
#define BPF_CONFIG_PATH BPF_MAPS_BASE "config"

static const char * const bpf_paths[MAX_ADDR_TYPE] = {
	BPF_MAPS_BASE "mac",
	BPF_MAPS_BASE "ip4",
	BPF_MAPS_BASE "ip6",
};

error_t *bpf_open(bpf_handle *hnd)
{
	int i;

	*hnd = (const bpf_handle){0};
	for (i = 0; i < MAX_ADDR_TYPE; i++) {
		if ((hnd->afds[i] = bpf_obj_get(bpf_paths[i])) == -1) {
			bpf_close(hnd);
			return errorf(E_BPF_OBJ_GET_FAIL, "'%s', %s", bpf_paths[i], strerror(errno));
		}
	}
	if ((hnd->cfd = bpf_obj_get(BPF_CONFIG_PATH)) == -1) {
		return errorf(E_BPF_OBJ_GET_FAIL, "'%s', %s", BPF_CONFIG_PATH, strerror(errno));
	}

	return NULL;
}

error_t *bpf_close(const bpf_handle *hnd)
{
	int i;

	for (i = 0; i < MAX_ADDR_TYPE; i++) {
		if (hnd->afds[i]) {
			close(hnd->afds[i]);
		}
	}
	if (hnd->cfd) {
		close(hnd->cfd);
	}

	return NULL;
}

error_t *bpf_lookup(const bpf_handle *hnd, const addr *addr, uint16_t *classid, bool *found)
{
	int fd = hnd->afds[addr->type];
	char astr[MAX_ADDR_STRLEN+1];

	if (bpf_lookup_elem(fd, &addr->val, classid) == -1) {
		if (errno != ENOENT) {
			return errorf(E_BPF_LOOKUP_ELEM_FAIL,
				"unable to find bpf entry for addr='%s', error='%s'",
				addr_str(addr, astr), strerror(errno));
		} else if (found) {
			*found = false;
		}
	} else if (found) {
		*found = true;
	}

	return NULL;
}

error_t *bpf_update(const bpf_handle *hnd, const addr *addr, const uint16_t classid,
	const uint64_t flags) 
{
	int fd = hnd->afds[addr->type];
	char astr[MAX_ADDR_STRLEN+1];

	if (bpf_update_elem(fd, &addr->val, &classid, flags) == -1) {
		return errorf(E_BPF_UPDATE_ELEM_FAIL,
			"unable to update bpf entry for addr='%s', error='%s'",
			addr_str(addr, astr), strerror(errno));
	}

	return NULL;
}

error_t *bpf_delete(const bpf_handle *hnd, const addr *addr)
{
	int fd = hnd->afds[addr->type];
	char astr[MAX_ADDR_STRLEN+1];

	if ((bpf_delete_elem(fd, &addr->val)) == -1) {
		return errorf(E_BPF_DELETE_ELEM_FAIL,
			"unable to delete bpf entry for addr='%s', error='%s'",
			addr_str(addr, astr), strerror(errno));
	}

	return NULL;
}

error_t *bpf_update_config(const bpf_handle *hnd, const bpf_config *bcfg)
{
	uint8_t ck = BPF_CONFIG_KEY;

	if (bpf_update_elem(hnd->cfd, &ck, bcfg, BPF_ANY) == -1) {
		return errorf(E_BPF_UPDATE_ELEM_FAIL,
			"unable to update bpf entry for key='%d', error='%s'", ck, strerror(errno));
	}

	return NULL;
}

bpf_it *bpf_new_it(const bpf_handle *hnd)
{
	bpf_it *it = malloc(sizeof(bpf_it));
	*it = (const bpf_it){0};
	it->hnd = hnd;

	return it;
}

error_t *bpf_next(bpf_it *it, addr *next, uint16_t *classid)
{
	error_t *err;
	int fd;

	while (!it->done) {
		fd = it->hnd->afds[it->addr_type];
		if ((bpf_get_next_key(fd, it->key, &next->val)) == -1) {
			if (errno != ENOENT) {
				return errorf(E_BPF_GET_NEXT_KEY_FAIL, "%s", strerror(errno));
			}
			it->key = NULL;
			if (++(it->addr_type) == MAX_ADDR_TYPE) {
				it->done = true;
			}
		} else {
			next->type = it->addr_type;
			it->key = &next->val;
			if (classid && ((err = bpf_lookup(it->hnd, next, classid, NULL)))) {
				return err;
			}
			break;
		}
	}

	return NULL;
}
