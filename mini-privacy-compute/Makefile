CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -pedantic -O2
INCDIR   = include
SRCDIR   = src
OBJDIR   = build
LIBDIR   = lib
EXDIR    = examples
DEMODIR  = demos
TESTDIR  = tests
BENDIR   = benches

SRCS     = $(wildcard $(SRCDIR)/*.c)
OBJS     = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
LIB      = $(LIBDIR)/libprivacycompute.a

EXAMPLES = $(EXDIR)/example_dp $(EXDIR)/example_fl $(EXDIR)/example_smpc
DEMOS    = $(DEMODIR)/demo_anonymization $(DEMODIR)/demo_pet $(DEMODIR)/demo_full
TEST     = $(TESTDIR)/test_core
BENCH    = $(BENDIR)/bench_core

.PHONY: all clean examples demos test bench build-lib

all: build-lib examples demos

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(LIB): $(OBJS)
	@mkdir -p $(LIBDIR)
	ar rcs $@ $^

build-lib: $(LIB)

$(EXDIR)/example_dp: $(EXDIR)/example_dp.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(EXDIR)/example_fl: $(EXDIR)/example_fl.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(EXDIR)/example_smpc: $(EXDIR)/example_smpc.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(DEMODIR)/demo_anonymization: $(DEMODIR)/demo_anonymization.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(DEMODIR)/demo_pet: $(DEMODIR)/demo_pet.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(DEMODIR)/demo_full: $(DEMODIR)/demo_full.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(TESTDIR)/test_core: $(TESTDIR)/test_core.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

$(BENDIR)/bench_core: $(BENDIR)/bench_core.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lprivacycompute -lm -o $@

examples: $(EXAMPLES)

demos: $(DEMOS)

test: $(TEST)
	@echo "=== Running Unit Tests ==="
	@powershell -NoProfile -Command "& './$(TEST).exe' *>&1; exit $$LASTEXITCODE"

bench: $(BENCH)
	@echo "=== Running Benchmarks ==="
	@powershell -NoProfile -Command "& './$(BENCH).exe' *>&1; exit $$LASTEXITCODE"

clean:
	rm -rf $(OBJDIR) $(LIBDIR)
	rm -f $(EXDIR)/example_dp $(EXDIR)/example_fl $(EXDIR)/example_smpc
	rm -f $(EXDIR)/*.exe
	rm -f $(DEMODIR)/demo_anonymization $(DEMODIR)/demo_pet $(DEMODIR)/demo_full
	rm -f $(DEMODIR)/*.exe
	rm -f $(TESTDIR)/test_core $(TESTDIR)/*.exe
	rm -f $(BENDIR)/bench_core $(BENDIR)/*.exe
