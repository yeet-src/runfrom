.PHONY: all clean

# A failed/interrupted bpftool dump must not leave a partial vmlinux.h
# behind — make would treat the half-written file as up to date and the
# build would fail confusingly downstream. Delete targets on recipe error.
.DELETE_ON_ERROR:

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
CLANG   ?= clang
BPFTOOL ?= sudo bpftool

LIBBPF_INCLUDE := /usr/include

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -Iinclude -I$(LIBBPF_INCLUDE)

all: runfrom.bpf.o

# struct linux_binprm (the exec path, creds, and backing inode) and struct
# task_struct (parent lineage) come from the running kernel's BTF — CO-RE,
# no system linux/*.h headers needed.
include/vmlinux.h:
	@mkdir -p include
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

runfrom.bpf.o: runfrom.bpf.c include/vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f runfrom.bpf.o include/vmlinux.h
