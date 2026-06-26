CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O2
LDFLAGS =

OBJS = iam_policy.o kms_key.o waf_rules.o ddos_protect.o container_security.o
HEADERS = iam_policy.h kms_key.h waf_rules.h ddos_protect.h container_security.h

EXAMPLES = example_iam example_kms example_waf
DEMOS = demo_cloud_security demo_security_sim

.PHONY: all clean examples demos

all: $(OBJS) $(EXAMPLES) $(DEMOS)

iam_policy.o: iam_policy.c iam_policy.h
	$(CC) $(CFLAGS) -c iam_policy.c -o iam_policy.o

kms_key.o: kms_key.c kms_key.h
	$(CC) $(CFLAGS) -c kms_key.c -o kms_key.o

waf_rules.o: waf_rules.c waf_rules.h
	$(CC) $(CFLAGS) -c waf_rules.c -o waf_rules.o

ddos_protect.o: ddos_protect.c ddos_protect.h
	$(CC) $(CFLAGS) -c ddos_protect.c -o ddos_protect.o

container_security.o: container_security.c container_security.h
	$(CC) $(CFLAGS) -c container_security.c -o container_security.o

example_iam: example_iam.c $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) example_iam.c $(OBJS) -o example_iam $(LDFLAGS)

example_kms: example_kms.c $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) example_kms.c $(OBJS) -o example_kms $(LDFLAGS)

example_waf: example_waf.c $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) example_waf.c $(OBJS) -o example_waf $(LDFLAGS)

examples: $(EXAMPLES)

demo_cloud_security: demo_cloud_security.c $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) demo_cloud_security.c $(OBJS) -o demo_cloud_security $(LDFLAGS)

demo_security_sim: demo_security_sim.c $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) demo_security_sim.c $(OBJS) -o demo_security_sim $(LDFLAGS)

demos: $(DEMOS)

clean:
	del /q $(OBJS) $(EXAMPLES:%=%.exe) $(DEMOS:%=%.exe) 2>nul || rm -f $(OBJS) $(EXAMPLES) $(DEMOS)
