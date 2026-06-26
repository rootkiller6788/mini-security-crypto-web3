CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O2 -I include -I src
LDFLAGS = -lm

SRC_DIR = src
INC_DIR = include
TST_DIR = tests
EXA_DIR = examples
DMO_DIR = examples

OBJS = iam_policy.o kms_key.o waf_rules.o ddos_protect.o container_security.o cloud_audit.o vpc_security.o

EXAMPLES = example_iam example_kms example_waf
DEMOS = demo_cloud_security demo_security_sim
TEST_BIN = test_core

.PHONY: all clean examples demos test

all: $(OBJS) $(EXAMPLES) $(DEMOS)

iam_policy.o: $(SRC_DIR)/iam_policy.c $(INC_DIR)/iam_policy.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/iam_policy.c -o iam_policy.o

kms_key.o: $(SRC_DIR)/kms_key.c $(INC_DIR)/kms_key.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/kms_key.c -o kms_key.o

waf_rules.o: $(SRC_DIR)/waf_rules.c $(INC_DIR)/waf_rules.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/waf_rules.c -o waf_rules.o

ddos_protect.o: $(SRC_DIR)/ddos_protect.c $(INC_DIR)/ddos_protect.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/ddos_protect.c -o ddos_protect.o

container_security.o: $(SRC_DIR)/container_security.c $(INC_DIR)/container_security.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/container_security.c -o container_security.o

cloud_audit.o: $(SRC_DIR)/cloud_audit.c $(INC_DIR)/cloud_audit.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/cloud_audit.c -o cloud_audit.o

vpc_security.o: $(SRC_DIR)/vpc_security.c $(INC_DIR)/vpc_security.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/vpc_security.c -o vpc_security.o

example_iam: $(EXA_DIR)/example_iam.c $(OBJS)
	$(CC) $(CFLAGS) $(EXA_DIR)/example_iam.c $(OBJS) -o example_iam $(LDFLAGS)

example_kms: $(EXA_DIR)/example_kms.c $(OBJS)
	$(CC) $(CFLAGS) $(EXA_DIR)/example_kms.c $(OBJS) -o example_kms $(LDFLAGS)

example_waf: $(EXA_DIR)/example_waf.c $(OBJS)
	$(CC) $(CFLAGS) $(EXA_DIR)/example_waf.c $(OBJS) -o example_waf $(LDFLAGS)

examples: $(EXAMPLES)

demo_cloud_security: $(DMO_DIR)/demo_cloud_security.c $(OBJS)
	$(CC) $(CFLAGS) $(DMO_DIR)/demo_cloud_security.c $(OBJS) -o demo_cloud_security $(LDFLAGS)

demo_security_sim: $(DMO_DIR)/demo_security_sim.c $(OBJS)
	$(CC) $(CFLAGS) $(DMO_DIR)/demo_security_sim.c $(OBJS) -o demo_security_sim $(LDFLAGS)

demos: $(DEMOS)

test_core: $(TST_DIR)/test_core.c $(OBJS)
	$(CC) $(CFLAGS) $(TST_DIR)/test_core.c $(OBJS) -o test_core $(LDFLAGS)

test: test_core
	./test_core.exe

clean:
	rm -f $(OBJS) $(EXAMPLES) $(DEMOS) test_core test_core.exe
	rm -f *.exe
