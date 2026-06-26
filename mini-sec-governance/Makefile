CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2
LDFLAGS = -lm

OBJ = iso27001_mgr.o soc2_audit.o nist_csf.o risk_assess.o compliance_auto.o
LIB = libsecgovernance.a
INC = -I.

EXAMPLES = example_iso27001.exe example_soc2.exe example_nist.exe
DEMOS = demo_risk_assess.exe demo_compliance_auto.exe

.PHONY: all clean examples demos

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

example_iso27001.exe: example_iso27001.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

example_soc2.exe: example_soc2.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

example_nist.exe: example_nist.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

demo_risk_assess.exe: demo_risk_assess.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

demo_compliance_auto.exe: demo_compliance_auto.c $(LIB)
	$(CC) $(CFLAGS) $(INC) $< -L. -lsecgovernance $(LDFLAGS) -o $@

examples: $(EXAMPLES)
	@echo "=== ISO 27001 Example ===" && example_iso27001.exe
	@echo "=== SOC 2 Example ===" && example_soc2.exe
	@echo "=== NIST CSF Example ===" && example_nist.exe

demos: $(DEMOS)
	@echo "=== Risk Assessment Demo ===" && demo_risk_assess.exe
	@echo "=== Compliance Automation Demo ===" && demo_compliance_auto.exe

clean:
	del /f *.o *.a *.exe 2>nul || rm -f *.o *.a *.exe
