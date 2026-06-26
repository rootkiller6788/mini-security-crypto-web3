CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -O2
LDFLAGS =
TARGETS = example_basic example_intermediate example_advanced demo_server demo_cli

SRC_SHARED = xss_csrf.c sqli_inject.c owasp_top10.c input_validation.c auth_session.c
OBJ_SHARED = $(SRC_SHARED:.c=.o)

.PHONY: all clean run_basic run_intermediate run_advanced run_server run_cli test

all: $(TARGETS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

example_basic: example_basic.c $(OBJ_SHARED)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

example_intermediate: example_intermediate.c $(OBJ_SHARED)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

example_advanced: example_advanced.c $(OBJ_SHARED)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

demo_server: demo_server.c $(OBJ_SHARED)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

demo_cli: demo_cli.c $(OBJ_SHARED)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

test: example_basic example_intermediate example_advanced demo_cli
	@echo "=== Running basic example ==="
	./example_basic
	@echo ""
	@echo "=== Running intermediate example ==="
	./example_intermediate
	@echo ""
	@echo "=== Running advanced example ==="
	./example_advanced
	@echo ""
	@echo "=== Running CLI demo ==="
	./demo_cli --help

run_basic: example_basic
	./example_basic

run_intermediate: example_intermediate
	./example_intermediate

run_advanced: example_advanced
	./example_advanced

run_server: demo_server
	./demo_server

run_cli: demo_cli
	./demo_cli --help

clean:
	@$(RM) *.o $(TARGETS) *.exe
