BPF_OBJ=tc_router_kern.o
BPF_SRC=src/tc_router_kern.c
USER_BIN=tc_router
USER_SRC=src/tc_router_user.c

CC=clang
CFLAGS=-O2 -g -Wall -Wextra
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86

LIBBPF_CFLAGS=$(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDFLAGS=$(shell pkg-config --libs libbpf 2>/dev/null)

all: $(BPF_OBJ) $(USER_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(CC) $(BPF_CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC) $(BPF_OBJ)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LDFLAGS) -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)

.PHONY: all clean
