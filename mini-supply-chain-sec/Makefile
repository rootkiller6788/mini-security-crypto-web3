CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -O2
INCDIR  = include
SRCDIR  = src
EXDIR   = examples
DEMDIR  = demos

LDFLAGS = -lm
AR      = ar
ARFLAGS = rcs

SOURCES = $(SRCDIR)/sbom_gen.c \
          $(SRCDIR)/slsa_framework.c \
          $(SRCDIR)/sigstore_cosign.c \
          $(SRCDIR)/dep_vuln.c \
          $(SRCDIR)/provenance_model.c

OBJECTS = $(SOURCES:.c=.o)

EXAMPLE_SRC = $(EXDIR)/ex1_sbom_basic.c \
              $(EXDIR)/ex2_cosign_sign.c \
              $(EXDIR)/ex3_vuln_scan.c

EXAMPLES = $(EXAMPLE_SRC:.c=.exe)

DEMO_SRC = $(DEMDIR)/demo1_slsa_pipeline.c \
           $(DEMDIR)/demo2_provenance_e2e.c

DEMOS = $(DEMO_SRC:.c=.exe)

LIBNAME  = libsupplychainsec
STATIC   = $(LIBNAME).a

.PHONY: all clean test demo

all: $(STATIC) $(EXAMPLES) $(DEMOS)

$(STATIC): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(EXDIR)/%.exe: $(EXDIR)/%.c $(STATIC)
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(STATIC) $(LDFLAGS) -o $@

$(DEMDIR)/%.exe: $(DEMDIR)/%.c $(STATIC)
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(STATIC) $(LDFLAGS) -o $@

test: $(EXAMPLES)
	@for e in $(EXAMPLES); do echo "Running $$e..."; ./$$e || exit 1; done

demo: $(DEMOS)
	@for d in $(DEMOS); do echo "Running $$d..."; ./$$d || exit 1; done

clean:
	del /q $(SRCDIR)\*.o 2>nul
	del /q $(STATIC) 2>nul
	del /q $(EXDIR)\*.exe 2>nul
	del /q $(DEMDIR)\*.exe 2>nul
