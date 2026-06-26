CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -O2
AR      = ar
ARFLAGS = rcs

INCDIR  = include
SRCDIR  = src
OBJDIR  = obj
LIBDIR  = lib
BINDIR  = bin

SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
LIB     = $(LIBDIR)/libai_security.a

EXAMPLES_SRC = $(wildcard examples/*.c)
EXAMPLES_BIN = $(patsubst examples/%.c, $(BINDIR)/%, $(EXAMPLES_SRC))

DEMOS_SRC    = $(wildcard demos/*.c)
DEMOS_BIN    = $(patsubst demos/%.c, $(BINDIR)/%, $(DEMOS_SRC))

.PHONY: all lib examples demos clean dirs

all: dirs lib examples demos

lib: dirs $(LIB)

examples: dirs $(EXAMPLES_BIN)

demos: dirs $(DEMOS_BIN)

dirs:
	@if not exist "$(OBJDIR)" mkdir "$(OBJDIR)"
	@if not exist "$(LIBDIR)" mkdir "$(LIBDIR)"
	@if not exist "$(BINDIR)" mkdir "$(BINDIR)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BINDIR)/%: examples/%.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lai_security -o $@ -lm

$(BINDIR)/%: demos/%.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(LIBDIR) -lai_security -o $@ -lm

run_example_adversarial: $(BINDIR)/example_adversarial
	$(BINDIR)/example_adversarial

run_example_inversion: $(BINDIR)/example_inversion
	$(BINDIR)/example_inversion

run_example_governance: $(BINDIR)/example_governance
	$(BINDIR)/example_governance

run_demo_adversarial: $(BINDIR)/demo_adversarial_training
	$(BINDIR)/demo_adversarial_training

run_demo_data_poison: $(BINDIR)/demo_data_poison
	$(BINDIR)/demo_data_poison

clean:
	@if exist "$(OBJDIR)" rmdir /s /q "$(OBJDIR)"
	@if exist "$(LIBDIR)" rmdir /s /q "$(LIBDIR)"
	@if exist "$(BINDIR)" rmdir /s /q "$(BINDIR)"
