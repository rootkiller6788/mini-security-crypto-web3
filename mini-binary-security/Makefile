.PHONY: all lib examples demos clean run

CC       ?= gcc
CFLAGS   ?= -std=c99 -Wall -Wextra -O2 -g
INCDIR   := include
SRCDIR   := src
OBJDIR   := build
LIBDIR   := lib
EXAMPLEDIR := examples
DEMODIR    := demos

INC      := -I$(INCDIR)
LDFLAGS  :=

HEADERS  := $(wildcard $(INCDIR)/*.h)
SOURCES  := $(wildcard $(SRCDIR)/*.c)
OBJECTS  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

EXAMPLES := $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLE_BINS := $(patsubst $(EXAMPLEDIR)/%.c,$(EXAMPLEDIR)/%.exe,$(EXAMPLES))

DEMOS    := $(wildcard $(DEMODIR)/*.c)
DEMO_BINS   := $(patsubst $(DEMODIR)/%.c,$(DEMODIR)/%.exe,$(DEMOS))

LIBNAME  := libbinarysecurity.a
LIBFILE  := $(LIBDIR)/$(LIBNAME)

all: lib examples demos
	@echo [OK] All targets built.

lib: $(LIBFILE)
	@echo [LIB] Library built: $(LIBFILE)

$(OBJDIR):
	@if not exist "$(OBJDIR)" mkdir "$(OBJDIR)"

$(LIBDIR):
	@if not exist "$(LIBDIR)" mkdir "$(LIBDIR)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(LIBFILE): $(OBJECTS) | $(LIBDIR)
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
	@echo.
	@echo === Running Examples ===
	@for %%f in ($(EXAMPLE_BINS)) do @echo --- %%~nxf --- && "%%f" && echo.
	@echo === Running Demos ===
	@for %%f in ($(DEMO_BINS)) do @echo --- %%~nxf --- && "%%f" && echo.

clean:
	@if exist "$(OBJDIR)" rmdir /s /q "$(OBJDIR)"
	@if exist "$(LIBDIR)" rmdir /s /q "$(LIBDIR)"
	@for %%f in ($(EXAMPLE_BINS)) do @if exist "%%f" del /q "%%f"
	@for %%f in ($(DEMO_BINS)) do @if exist "%%f" del /q "%%f"
	@echo [CLEAN] Done.
