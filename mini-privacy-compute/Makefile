CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -pedantic -O2
INCDIR   = include
SRCDIR   = src
OBJDIR   = build
LIBDIR   = lib
EXDIR    = examples
DEMODIR  = demos

SRCS     = $(wildcard $(SRCDIR)/*.c)
OBJS     = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
LIB      = $(LIBDIR)/libprivacycompute.a

EXAMPLES = $(EXDIR)/example_dp $(EXDIR)/example_fl $(EXDIR)/example_smpc
DEMOS    = $(DEMODIR)/demo_anonymization $(DEMODIR)/demo_pet

.PHONY: all clean examples demos lib

all: lib examples demos

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@if not exist "$(OBJDIR)" mkdir "$(OBJDIR)"
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(LIB): $(OBJS)
	@if not exist "$(LIBDIR)" mkdir "$(LIBDIR)"
	ar rcs $@ $^

lib: $(LIB)

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

examples: $(EXAMPLES)

demos: $(DEMOS)

clean:
	@if exist "$(OBJDIR)" rmdir /s /q "$(OBJDIR)"
	@if exist "$(LIBDIR)" rmdir /s /q "$(LIBDIR)"
	@for %%f in ($(EXAMPLES) $(DEMOS)) do @if exist "%%f.exe" del "%%f.exe"
