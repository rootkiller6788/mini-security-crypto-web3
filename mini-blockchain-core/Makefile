CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -O2 -Iinclude
LDFLAGS  = -L.
LDLIBS   = -lssl -lcrypto
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
       $(SRCDIR)/p2p_network.c

OBJS = $(SRCS:$(SRCDIR)/%.c=$(BLDDIR)/%.o)

EXAMPLES = $(BLDDIR)/example_utxo.exe \
           $(BLDDIR)/example_merkle.exe \
           $(BLDDIR)/example_pow.exe

DEMOS = $(BLDDIR)/demo_blockchain.exe \
        $(BLDDIR)/demo_wallet.exe

.PHONY: all clean examples demos lib

all: lib examples demos

lib: $(BLDDIR)/$(LIBNAME)

$(BLDDIR):
	@if not exist "$(BLDDIR)" mkdir "$(BLDDIR)"

$(BLDDIR)/%.o: $(SRCDIR)/%.c | $(BLDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BLDDIR)/$(LIBNAME): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BLDDIR)/example_utxo.exe: $(EXADIR)/example_utxo.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/example_merkle.exe: $(EXADIR)/example_merkle.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/example_pow.exe: $(EXADIR)/example_pow.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/demo_blockchain.exe: $(DEMDIR)/demo_blockchain.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

$(BLDDIR)/demo_wallet.exe: $(DEMDIR)/demo_wallet.c $(BLDDIR)/$(LIBNAME)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lblockchain $(LDLIBS)

examples: $(EXAMPLES)

demos: $(DEMOS)

clean:
	@if exist "$(BLDDIR)" rmdir /s /q "$(BLDDIR)"
