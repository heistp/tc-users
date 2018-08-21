#ifndef __BPFLIB_H
#define __BPFLIB_H

int bpf_obj_get(const char *pathname);

int bpf_get_next_key(const int fd, const void *key, void *next_key);

int bpf_lookup_elem(const int fd, const void *key, void *value);

int bpf_update_elem(const int fd, const void *key, const void *value, const unsigned long long flags);

int bpf_delete_elem(const int fd, const void *key);

#endif
