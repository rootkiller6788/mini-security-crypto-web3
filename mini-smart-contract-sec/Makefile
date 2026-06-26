CC = cc
CFLAGS = -std=c99 -Wall -Wextra -O2 -pedantic -Isrc -Iinclude -Wno-restrict -Wno-stringop-truncation
LDFLAGS = -lm
EXEEXT = .exe

SRC = src/evm_sim.c src/reentrancy_check.c src/overflow_detect.c src/access_control.c src/formal_verify.c src/gas_optimizer.c src/evm_disasm.c
HDR = include/evm_sim.h include/reentrancy_check.h include/overflow_detect.h include/access_control.h include/formal_verify.h include/gas_optimizer.h include/evm_disasm.h
OBJ = evm_sim.o reentrancy_check.o overflow_detect.o access_control.o formal_verify.o gas_optimizer.o evm_disasm.o

EXAMPLES = example_reentrancy example_overflow example_access
DEMOS = demo_full_audit demo_verify
TEST_BIN = test_core

.PHONY: all clean test

all: libmini_scsec.a $(EXAMPLES) $(DEMOS)

libmini_scsec.a: $(OBJ)
	$(AR) rcs $@ $(OBJ)

evm_sim.o: src/evm_sim.c $(HDR)
	$(CC) $(CFLAGS) -c src/evm_sim.c -o $@

reentrancy_check.o: src/reentrancy_check.c $(HDR)
	$(CC) $(CFLAGS) -c src/reentrancy_check.c -o $@

overflow_detect.o: src/overflow_detect.c $(HDR)
	$(CC) $(CFLAGS) -c src/overflow_detect.c -o $@

access_control.o: src/access_control.c $(HDR)
	$(CC) $(CFLAGS) -c src/access_control.c -o $@

formal_verify.o: src/formal_verify.c $(HDR)
	$(CC) $(CFLAGS) -c src/formal_verify.c -o $@

gas_optimizer.o: src/gas_optimizer.c $(HDR)
	$(CC) $(CFLAGS) -c src/gas_optimizer.c -o $@

evm_disasm.o: src/evm_disasm.c $(HDR)
	$(CC) $(CFLAGS) -c src/evm_disasm.c -o $@

example_reentrancy: examples/example_reentrancy.c libmini_scsec.a
	$(CC) $(CFLAGS) examples/example_reentrancy.c -L. -lmini_scsec $(LDFLAGS) -o $@

example_overflow: examples/example_overflow.c libmini_scsec.a
	$(CC) $(CFLAGS) examples/example_overflow.c -L. -lmini_scsec $(LDFLAGS) -o $@

example_access: examples/example_access.c libmini_scsec.a
	$(CC) $(CFLAGS) examples/example_access.c -L. -lmini_scsec $(LDFLAGS) -o $@

demo_full_audit: examples/demo_full_audit.c libmini_scsec.a
	$(CC) $(CFLAGS) examples/demo_full_audit.c -L. -lmini_scsec $(LDFLAGS) -o $@

demo_verify: examples/demo_verify.c libmini_scsec.a
	$(CC) $(CFLAGS) examples/demo_verify.c -L. -lmini_scsec $(LDFLAGS) -o $@

test: all
	@echo "=== Running Examples ==="
	@echo "--- Reentrancy Example ---"
	./example_reentrancy$(EXEEXT) || true
	@echo "--- Overflow Example ---"
	./example_overflow$(EXEEXT) || true
	@echo "--- Access Example ---"
	./example_access$(EXEEXT) || true
	@echo "--- Demo: Full Audit ---"
	./demo_full_audit$(EXEEXT) || true
	@echo "--- Demo: Verify ---"
	./demo_verify$(EXEEXT) || true
	@echo "=== All tests completed ==="

clean:
	rm -f $(OBJ) libmini_scsec.a $(EXAMPLES) $(DEMOS) $(TEST_BIN)
	rm -f *.exe
