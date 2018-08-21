CC=clang
LD=llc
OUTPUT_OPTION=-MMD -MP -o $@
CFLAGS=-O2 -Wall

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
DEP=$(SRC:.c=.d)

.PHONY: clean

all: tc-users tc-users-bpf.o

tc-users: tc-users.o input.o classify.o sync.o \
	addr.o bpf.o bpf_config.o bpflib.o config.o entry.o error.o log.o

tc-users-bpf.o: tc-users-bpf.c
	$(CC) $(CFLAGS) -target bpf -c tc-users-bpf.c

-include $(DEP)

clean:
	rm -f $(OBJ) $(DEP) tc-users
