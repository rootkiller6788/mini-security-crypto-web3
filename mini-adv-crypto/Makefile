CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -O2 -march=native -Iinclude
LDFLAGS = -lm

SRC_DIR = src
INC_DIR = include
EXA_DIR = examples
TST_DIR = tests

SRCS    = $(SRC_DIR)/zk_proof.c $(SRC_DIR)/homomorphic_enc.c $(SRC_DIR)/mpc_proto.c \
          $(SRC_DIR)/post_quantum.c $(SRC_DIR)/threshold_sig.c \
          $(SRC_DIR)/crypto_theorems.c $(SRC_DIR)/crypto_apps.c $(SRC_DIR)/crypto_advanced.c
OBJS    = zk_proof.o homomorphic_enc.o mpc_proto.o post_quantum.o threshold_sig.o \
          crypto_theorems.o crypto_apps.o crypto_advanced.o

EXAMPLES = example_zk example_he example_mpc
DEMOS    = demo_full demo_bench

.PHONY: all clean examples demos test run_zk run_he run_mpc run_full run_bench

all: libminicrypto.a

libminicrypto.a: $(OBJS)
	ar rcs $@ $^

# Pattern: compile src/xxx.c -> xxx.o
zk_proof.o: $(SRC_DIR)/zk_proof.c $(INC_DIR)/zk_proof.h
	$(CC) $(CFLAGS) -c $< -o $@

homomorphic_enc.o: $(SRC_DIR)/homomorphic_enc.c $(INC_DIR)/homomorphic_enc.h
	$(CC) $(CFLAGS) -c $< -o $@

mpc_proto.o: $(SRC_DIR)/mpc_proto.c $(INC_DIR)/mpc_proto.h
	$(CC) $(CFLAGS) -c $< -o $@

post_quantum.o: $(SRC_DIR)/post_quantum.c $(INC_DIR)/post_quantum.h
	$(CC) $(CFLAGS) -c $< -o $@

threshold_sig.o: $(SRC_DIR)/threshold_sig.c $(INC_DIR)/threshold_sig.h
	$(CC) $(CFLAGS) -c $< -o $@

crypto_theorems.o: $(SRC_DIR)/crypto_theorems.c $(INC_DIR)/crypto_theorems.h
	$(CC) $(CFLAGS) -c $< -o $@

crypto_apps.o: $(SRC_DIR)/crypto_apps.c $(INC_DIR)/crypto_apps.h
	$(CC) $(CFLAGS) -c $< -o $@

crypto_advanced.o: $(SRC_DIR)/crypto_advanced.c $(INC_DIR)/crypto_advanced.h
	$(CC) $(CFLAGS) -c $< -o $@

example_zk.exe: $(EXA_DIR)/example_zk.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

example_he.exe: $(EXA_DIR)/example_he.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

example_mpc.exe: $(EXA_DIR)/example_mpc.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

demo_full.exe: $(EXA_DIR)/demo_full.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

demo_bench.exe: $(EXA_DIR)/demo_bench.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

test_core.exe: $(TST_DIR)/test_core.c libminicrypto.a
	$(CC) $(CFLAGS) -I$(INC_DIR) $< -L. -lminicrypto $(LDFLAGS) -o $@

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

run_test: test_core.exe
	./test_core.exe

test: all examples demos test_core.exe
	@echo "=== Running unit tests ==="
	./test_core.exe
	@echo "=== Running examples ==="
	./example_zk.exe
	./example_he.exe
	./example_mpc.exe
	@echo "=== Running demos ==="
	./demo_full.exe
	./demo_bench.exe
	@echo "=== All tests passed ==="

clean:
	rm -f *.o *.a *.exe
