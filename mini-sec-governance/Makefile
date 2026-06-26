CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2
LDFLAGS = -lm

SRC_DIR = src
INC_DIR = include
TST_DIR = tests
EXA_DIR = examples
DMO_DIR = demos
BNH_DIR = benches

SRCS = $(SRC_DIR)/iso27001_mgr.c $(SRC_DIR)/soc2_audit.c $(SRC_DIR)/nist_csf.c \
       $(SRC_DIR)/risk_assess.c $(SRC_DIR)/compliance_auto.c
OBJS = $(SRCS:.c=.o)
LIB  = libsecgovernance.a
INC  = -I$(INC_DIR)

TEST_SRC = $(TST_DIR)/test_core.c
TEST_EXE = test_core.exe

EXAMPLES_SRC = $(EXA_DIR)/example_iso27001.c $(EXA_DIR)/example_soc2.c $(EXA_DIR)/example_nist.c
EXAMPLES_EXE = $(EXAMPLES_SRC:$(EXA_DIR)/%.c=%.exe)

DEMOS_SRC = $(EXA_DIR)/demo_risk_assess.c $(EXA_DIR)/demo_compliance_auto.c
DEMOS_EXE = $(DEMOS_SRC:$(EXA_DIR)/%.c=%.exe)

FULL_DEMO_SRC = $(DMO_DIR)/demo_full.c
FULL_DEMO_EXE = demo_full.exe

BENCH_SRC = $(BNH_DIR)/bench_core.c
BENCH_EXE = bench_core.exe

.PHONY: all clean test examples demos demo-full bench

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/%.h
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

# Tests
$(TEST_EXE): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

test: $(TEST_EXE)
	@echo "=== Running Tests ===" && ./$(TEST_EXE)

# Examples
example_iso27001.exe: $(EXA_DIR)/example_iso27001.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

example_soc2.exe: $(EXA_DIR)/example_soc2.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

example_nist.exe: $(EXA_DIR)/example_nist.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

examples: $(EXAMPLES_EXE)
	@echo "=== ISO 27001 Example ===" && ./example_iso27001.exe
	@echo "=== SOC 2 Example ===" && ./example_soc2.exe
	@echo "=== NIST CSF Example ===" && ./example_nist.exe

# Demos
demo_risk_assess.exe: $(EXA_DIR)/demo_risk_assess.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

demo_compliance_auto.exe: $(EXA_DIR)/demo_compliance_auto.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

demos: $(DEMOS_EXE)
	@echo "=== Risk Assessment Demo ===" && ./demo_risk_assess.exe
	@echo "=== Compliance Automation Demo ===" && ./demo_compliance_auto.exe

# Full demo
$(FULL_DEMO_EXE): $(FULL_DEMO_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

demo-full: $(FULL_DEMO_EXE)
	@echo "=== Full GRC Demo ===" && ./$(FULL_DEMO_EXE)

# Benchmarks
$(BENCH_EXE): $(BENCH_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

bench: $(BENCH_EXE)
	@echo "=== Benchmarks ===" && ./$(BENCH_EXE) 1000

clean:
	rm -f $(SRC_DIR)/*.o *.o *.a *.exe 2>/dev/null || true
	rm -f $(LIB) $(TEST_EXE) $(EXAMPLES_EXE) $(DEMOS_EXE) $(FULL_DEMO_EXE) $(BENCH_EXE) 2>/dev/null || true
