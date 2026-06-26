CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -std=c99 -I include
OUTDIR   = bin
SRCDIR   = src
EXAMPDIR = examples
DOCDIR   = docs

SRCS = $(SRCDIR)/hash_func.c \
       $(SRCDIR)/symmetric_cipher.c \
       $(SRCDIR)/asymmetric_cipher.c \
       $(SRCDIR)/digital_sig.c \
       $(SRCDIR)/pki_model.c

OBJS = $(SRCS:.c=.o)

EXAMPLES = demo_hash demo_aes_rsa demo_pki
EXE_FILES = $(addprefix $(OUTDIR)/, $(EXAMPLES))

.PHONY: all clean run-demos

all: dirs $(EXE_FILES)

dirs:
	if not exist $(OUTDIR) mkdir $(OUTDIR)

$(OUTDIR)/demo_hash: $(OBJS) $(EXAMPDIR)/demo_hash.c
	$(CC) $(CFLAGS) $(OBJS) $(EXAMPDIR)/demo_hash.c -o $@

$(OUTDIR)/demo_aes_rsa: $(OBJS) $(EXAMPDIR)/demo_aes_rsa.c
	$(CC) $(CFLAGS) $(OBJS) $(EXAMPDIR)/demo_aes_rsa.c -o $@

$(OUTDIR)/demo_pki: $(OBJS) $(EXAMPDIR)/demo_pki.c
	$(CC) $(CFLAGS) $(OBJS) $(EXAMPDIR)/demo_pki.c -o $@

run-demos: all
	@echo === Running demo_hash ===
	$(OUTDIR)/demo_hash
	@echo.
	@echo === Running demo_aes_rsa ===
	$(OUTDIR)/demo_aes_rsa
	@echo.
	@echo === Running demo_pki ===
	$(OUTDIR)/demo_pki

clean:
	del /q $(SRCDIR)\*.o 2>nul
	del /q $(OUTDIR)\*.exe 2>nul
	del /q $(OUTDIR)\* 2>nul
