CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -pedantic -O2
INCLUDES = -I.
LDFLAGS  =

SRCS     = sgx_enclave.c tdx_amd.c remote_attest.c confidential_comp.c tpm_trust.c
OBJS     = $(SRCS:.c=.o)

EXAMPLES = example_sgx example_tdx_sev example_tpm
DEMOS    = demo_attestation demo_confidential

all: examples demos

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

libmini-tc.a: $(OBJS)
	ar rcs $@ $^

example_sgx: example_sgx.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

example_tdx_sev: example_tdx_sev.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

example_tpm: example_tpm.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

demo_attestation: demo_attestation.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

demo_confidential: demo_confidential.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

examples: $(EXAMPLES)

demos: $(DEMOS)

run-examples: examples
	@echo "=== Running example_sgx ==="
	./example_sgx
	@echo ""
	@echo "=== Running example_tdx_sev ==="
	./example_tdx_sev
	@echo ""
	@echo "=== Running example_tpm ==="
	./example_tpm

run-demos: demos
	@echo "=== Running demo_attestation ==="
	./demo_attestation
	@echo ""
	@echo "=== Running demo_confidential ==="
	./demo_confidential

clean:
	del /f *.o 2>nul
	del /f *.a 2>nul
	del /f example_sgx.exe 2>nul
	del /f example_tdx_sev.exe 2>nul
	del /f example_tpm.exe 2>nul
	del /f demo_attestation.exe 2>nul
	del /f demo_confidential.exe 2>nul

.PHONY: all examples demos run-examples run-demos clean
