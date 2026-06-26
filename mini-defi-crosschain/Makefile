CC = gcc
CFLAGS = -Wall -Wextra -O2 -I include
LDFLAGS = -lm

MINGW_BIN = D:/msys64/mingw64/bin
MINGW_USR = D:/msys64/usr/bin
EXPORT_PATH = export PATH=$(MINGW_BIN):$(MINGW_USR):$$PATH

SRCDIR = src
EXDIR = examples
DEMDIR = demos
OUTDIR = bin

SRCS = $(SRCDIR)/amm_swap.c $(SRCDIR)/lending_proto.c $(SRCDIR)/stablecoin.c \
       $(SRCDIR)/crosschain_bridge.c $(SRCDIR)/oracle_price.c \
       $(SRCDIR)/yield_aggregator.c $(SRCDIR)/governance_dao.c \
       $(SRCDIR)/derivatives.c $(SRCDIR)/mev_protection.c

OBJS = $(SRCS:$(SRCDIR)/%.c=$(OUTDIR)/%.o)

EXAMPLES = example_amm example_lending example_oracle
DEMOS = demo_full_defi demo_crosschain

all: $(OBJS)
	@echo "All library objects compiled."

$(OUTDIR):
	@mkdir -p "$(OUTDIR)"

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) -c $< -o $@

example_amm: $(EXDIR)/example_amm.c $(OUTDIR)/amm_swap.o | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) $< $(OUTDIR)/amm_swap.o -o $(OUTDIR)/example_amm $(LDFLAGS)
	@echo "  Running example_amm..."
	$(OUTDIR)/example_amm

example_lending: $(EXDIR)/example_lending.c $(OUTDIR)/lending_proto.o $(OUTDIR)/oracle_price.o | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) $< $(OUTDIR)/lending_proto.o $(OUTDIR)/oracle_price.o -o $(OUTDIR)/example_lending $(LDFLAGS)
	@echo "  Running example_lending..."
	$(OUTDIR)/example_lending

example_oracle: $(EXDIR)/example_oracle.c $(OUTDIR)/oracle_price.o $(OUTDIR)/stablecoin.o | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) $< $(OUTDIR)/oracle_price.o $(OUTDIR)/stablecoin.o -o $(OUTDIR)/example_oracle $(LDFLAGS)
	@echo "  Running example_oracle..."
	$(OUTDIR)/example_oracle

demo_full_defi: $(DEMDIR)/demo_full_defi.c $(OUTDIR)/amm_swap.o $(OUTDIR)/lending_proto.o $(OUTDIR)/stablecoin.o $(OUTDIR)/oracle_price.o | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) $< $(OUTDIR)/amm_swap.o $(OUTDIR)/lending_proto.o $(OUTDIR)/stablecoin.o $(OUTDIR)/oracle_price.o -o $(OUTDIR)/demo_full_defi $(LDFLAGS)
	@echo "  Running demo_full_defi..."
	$(OUTDIR)/demo_full_defi

demo_crosschain: $(DEMDIR)/demo_crosschain.c $(OUTDIR)/crosschain_bridge.o $(OUTDIR)/amm_swap.o $(OUTDIR)/oracle_price.o | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) $< $(OUTDIR)/crosschain_bridge.o $(OUTDIR)/amm_swap.o $(OUTDIR)/oracle_price.o -o $(OUTDIR)/demo_crosschain $(LDFLAGS)
	@echo "  Running demo_crosschain..."
	$(OUTDIR)/demo_crosschain

test_core: $(OBJS) | $(OUTDIR)
	$(EXPORT_PATH) && $(CC) $(CFLAGS) tests/test_core.c $(OBJS) -o $(OUTDIR)/test_core $(LDFLAGS)
	@echo "  Running unit tests..."
	$(OUTDIR)/test_core

test: example_amm example_lending example_oracle demo_full_defi demo_crosschain test_core
	@echo ""
	@echo "========================================"
	@echo "  ALL TESTS COMPLETE"
	@echo "========================================"

clean:
	@rm -rf "$(OUTDIR)"
	@echo "Cleaned build artifacts."

.PHONY: all test test_core clean example_amm example_lending example_oracle demo_full_defi demo_crosschain
