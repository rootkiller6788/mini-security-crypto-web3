CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -Wno-deprecated-declarations -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter -Wno-misleading-indentation -Wno-implicit-fallthrough -O2 -Iinclude
LDFLAGS  = -L$(BLDDIR)
LDLIBS   = -lssl -lcrypto -lm -lws2_32
AR       = ar
ARFLAGS  = rcs

SRCDIR   = src
INCDIR   = include
EXADIR   = examples
DEMDIR   = demos
DOCDIR   = docs
BLDDIR   = build
LIBNAME  = libblockchain.a

SRCS = $(SRCDIR)/utxo_model.c \
       $(SRCDIR)/merkle_tree.c \
       $(SRCDIR)/consensus_pow.c \
       $(SRCDIR)/tx_pool.c \
       $(SRCDIR)/p2p_network.c \
       $(SRCDIR)/script_engine.c \
       $(SRCDIR)/spv_client.c

OBJS = $(SRCS:$(SRCDIR)/%.c=$(BLDDIR)/%.o)

EXAMPLES = $(BLDDIR)/example_utxo \
           $(BLDDIR)/example_merkle \
           $(BLDDIR)/example_pow
DEMOS = $(BLDDIR)/demo_blockchain \
        $(BLDDIR)/demo_wallet
TESTS = $(BLDDIR)/test_core
.PHONY: all clean examples demos lib test

all: lib examples demos test

test: $(TESTS)
	@echo === Running Tests ===
	@./$(BLDDIR)/test_core

lib: $(BLDDIR)/$(LIBNAME)

$(BLDDIR):
	@mkdir -p $(BLDDIR)

$(BLDDIR)/%.o: $(SRCDIR)/%.c | $(BLDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BLDDIR)/$(LIBNAME): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BLDDIR)/example_utxo: $(EXADIR)/example_utxo.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/example_merkle: $(EXADIR)/example_merkle.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/example_pow: $(EXADIR)/example_pow.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/demo_blockchain: $(DEMDIR)/demo_blockchain.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/demo_wallet: $(DEMDIR)/demo_wallet.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/test_core: tests/test_core.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

examples: $(EXAMPLES)

demos: $(DEMOS)

clean:
	@rm -rf $(BLDDIR)
