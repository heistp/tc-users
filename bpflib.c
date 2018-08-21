#include <linux/unistd.h>
#include <linux/bpf.h>
#include <unistd.h>

#include "bpflib.h"

static __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	attr = (const union bpf_attr){{0}};
	attr.pathname = ptr_to_u64((void *)pathname);

	return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_get_next_key(const int fd, const void *key, void *next_key)
{
	union bpf_attr attr;

	attr = (const union bpf_attr){{0}};
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int bpf_lookup_elem(const int fd, const void *key, void *value)
{
	union bpf_attr attr;

	attr = (const union bpf_attr){{0}};
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(const int fd, const void *key, const void *value, unsigned long long flags)
{
	union bpf_attr attr;

	attr = (const union bpf_attr){{0}};
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(const int fd, const void *key)
{
	union bpf_attr attr;

	attr = (const union bpf_attr){{0}};
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);

	return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}
