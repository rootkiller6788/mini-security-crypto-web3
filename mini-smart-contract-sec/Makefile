CC = cc
CFLAGS = -std=c99 -Wall -Wextra -O2 -pedantic
LDFLAGS = -lm

SRC = evm_sim.c reentrancy_check.c overflow_detect.c access_control.c formal_verify.c
HDR = evm_sim.h reentrancy_check.h overflow_detect.h access_control.h formal_verify.h
OBJ = $(SRC:.c=.o)

EXAMPLES = example_reentrancy example_overflow example_access
DEMOS = demo_full_audit demo_verify

.PHONY: all clean test

all: libmini_scsec.a $(EXAMPLES) $(DEMOS)

libmini_scsec.a: $(OBJ)
	$(AR) rcs $@ $(OBJ)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

example_reentrancy: example_reentrancy.c libmini_scsec.a
	$(CC) $(CFLAGS) $< -L. -lmini_scsec $(LDFLAGS) -o $@

example_overflow: example_overflow.c libmini_scsec.a
	$(CC) $(CFLAGS) $< -L. -lmini_scsec $(LDFLAGS) -o $@

example_access: example_access.c libmini_scsec.a
	$(CC) $(CFLAGS) $< -L. -lmini_scsec $(LDFLAGS) -o $@

demo_full_audit: demo_full_audit.c libmini_scsec.a
	$(CC) $(CFLAGS) $< -L. -lmini_scsec $(LDFLAGS) -o $@

demo_verify: demo_verify.c libmini_scsec.a
	$(CC) $(CFLAGS) $< -L. -lmini_scsec $(LDFLAGS) -o $@

test: all
	@echo "=== Running Examples ==="
	@echo "--- Reentrancy Example ---"
	./example_reentrancy
	@echo "--- Overflow Example ---"
	./example_overflow
	@echo "--- Access Example ---"
	./example_access
	@echo "--- Demo: Full Audit ---"
	./demo_full_audit
	@echo "--- Demo: Verify ---"
	./demo_verify

clean:
	rm -f $(OBJ) libmini_scsec.a $(EXAMPLES) $(DEMOS)
	rm -f *.exe
