.PHONY: all lib examples demos test clean run

CC       ?= gcc
CFLAGS   ?= -std=c99 -Wall -Wextra -O2 -g
INCDIR   := include
SRCDIR   := src
OBJDIR   := build
LIBDIR   := lib
EXAMPLEDIR := examples
DEMODIR    := demos
TESTDIR    := tests

INC      := -I$(INCDIR)
LDFLAGS  :=

HEADERS  := $(wildcard $(INCDIR)/*.h)
SOURCES  := $(wildcard $(SRCDIR)/*.c)
OBJECTS  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

EXAMPLES := $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLE_BINS := $(patsubst $(EXAMPLEDIR)/%.c,$(EXAMPLEDIR)/%.exe,$(EXAMPLES))

DEMOS    := $(wildcard $(DEMODIR)/*.c)
DEMO_BINS   := $(patsubst $(DEMODIR)/%.c,$(DEMODIR)/%.exe,$(DEMOS))

TESTS    := $(wildcard $(TESTDIR)/*.c)
TEST_BINS   := $(patsubst $(TESTDIR)/%.c,$(TESTDIR)/%.exe,$(TESTS))

LIBNAME  := libbinarysecurity.a
LIBFILE  := $(LIBDIR)/$(LIBNAME)

all: lib examples demos
	@echo [OK] All targets built.

lib: $(LIBFILE)
	@echo [LIB] Library built: $(LIBFILE)

$(OBJDIR):
	@mkdir -p "$(OBJDIR)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(LIBFILE): $(OBJECTS)
	@mkdir -p $(LIBDIR)
	ar rcs $@ $^
	@echo [AR] $@

examples: $(EXAMPLE_BINS)
	@echo [EXAMPLES] Built $(words $(EXAMPLE_BINS)) examples.

$(EXAMPLEDIR)/%.exe: $(EXAMPLEDIR)/%.c $(LIBFILE) $(HEADERS)
	$(CC) $(CFLAGS) $(INC) -o $@ $< -L$(LIBDIR) -lbinarysecurity $(LDFLAGS)

demos: $(DEMO_BINS)
	@echo [DEMOS] Built $(words $(DEMO_BINS)) demos.

$(DEMODIR)/%.exe: $(DEMODIR)/%.c $(LIBFILE) $(HEADERS)
	$(CC) $(CFLAGS) $(INC) -o $@ $< -L$(LIBDIR) -lbinarysecurity $(LDFLAGS)

run: all
	@echo ""
	@echo "=== Running Examples ==="
	@for f in $(EXAMPLE_BINS); do echo "--- $$f ---" && "$$f" && echo ""; done
	@echo "=== Running Demos ==="
	@for f in $(DEMO_BINS); do echo "--- $$f ---" && "$$f" && echo ""; done

clean:
	@rm -rf "$(OBJDIR)" "$(LIBDIR)"
	@rm -f $(EXAMPLE_BINS) $(DEMO_BINS) $(TEST_BINS)
	@echo [CLEAN] Done.

test: lib $(TEST_BINS)
	@echo "[TEST] Running tests..."
	@for f in $(TEST_BINS); do echo "--- $$f ---" && "$$f" && echo ""; done
	@echo "[TEST] All tests complete."

$(TESTDIR)/%.exe: $(TESTDIR)/%.c $(LIBFILE) $(HEADERS)
	$(CC) $(CFLAGS) $(INC) -o $@ $< -L$(LIBDIR) -lbinarysecurity $(LDFLAGS)
