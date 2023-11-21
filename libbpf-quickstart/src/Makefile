CLANG   = clang
GCC     = gcc
CFLAGS  = -O2 -target bpf
LDFLAGS = -g -Wall -lbpf

BPF_SRC = c/dplane.bpf.c
BPF_OBJ = dplane.bpf.o

PROG_SRC = c/main.c
PROG_OBJ = main.o
PROG_BIN = main

all: $(BPF_OBJ) $(PROG_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@ -g
	bpftool gen skeleton $(BPF_OBJ) > c/bpf_dplane.h

$(PROG_OBJ): $(PROG_SRC)
	$(GCC) $(LDFLAGS) -c $< -o $@ 

$(PROG_BIN): $(PROG_OBJ)
	$(GCC) -o $@ $(PROG_OBJ) $(LDFLAGS)
	chmod a+x $(PROG_BIN)
	rm $(PROG_OBJ)

clean:
	rm -f $(BPF_OBJ) $(PROG_BIN)
