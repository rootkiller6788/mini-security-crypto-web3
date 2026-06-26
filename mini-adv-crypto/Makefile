CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -O2 -march=native
LDFLAGS = -lm

SRCS    = zk_proof.c homomorphic_enc.c mpc_proto.c post_quantum.c threshold_sig.c
OBJS    = $(SRCS:.c=.o)
HDRS    = zk_proof.h homomorphic_enc.h mpc_proto.h post_quantum.h threshold_sig.h

EXAMPLES = example_zk example_he example_mpc
DEMOS    = demo_full demo_bench

.PHONY: all clean examples demos test run_zk run_he run_mpc run_full run_bench

all: libminicrypto.a

libminicrypto.a: $(OBJS)
	ar rcs $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

example_zk.exe: example_zk.c libminicrypto.a
	$(CC) $(CFLAGS) $< -L. -lminicrypto $(LDFLAGS) -o $@

example_he.exe: example_he.c libminicrypto.a
	$(CC) $(CFLAGS) $< -L. -lminicrypto $(LDFLAGS) -o $@

example_mpc.exe: example_mpc.c libminicrypto.a
	$(CC) $(CFLAGS) $< -L. -lminicrypto $(LDFLAGS) -o $@

demo_full.exe: demo_full.c libminicrypto.a
	$(CC) $(CFLAGS) $< -L. -lminicrypto $(LDFLAGS) -o $@

demo_bench.exe: demo_bench.c libminicrypto.a
	$(CC) $(CFLAGS) $< -L. -lminicrypto $(LDFLAGS) -o $@

examples: libminicrypto.a example_zk.exe example_he.exe example_mpc.exe

demos: libminicrypto.a demo_full.exe demo_bench.exe

run_zk: example_zk.exe
	./example_zk.exe

run_he: example_he.exe
	./example_he.exe

run_mpc: example_mpc.exe
	./example_mpc.exe

run_full: demo_full.exe
	./demo_full.exe

run_bench: demo_bench.exe
	./demo_bench.exe

test: all examples
	@echo "=== Running all examples ==="
	./example_zk.exe
	./example_he.exe
	./example_mpc.exe
	@echo "=== Running demos ==="
	./demo_full.exe
	./demo_bench.exe
	@echo "=== All tests passed ==="

clean:
	del /f *.o *.a *.exe 2>nul || rm -f *.o *.a *.exe
