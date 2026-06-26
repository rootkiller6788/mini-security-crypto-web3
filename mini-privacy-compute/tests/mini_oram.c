#include "secure_mpc_comp.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    printf("Test: oram\n");
    ORAMServer oram;
    oram_init(&oram, 32, 16);
    uint8_t wdata[16] = "hello_oram";
    oram_access(&oram, 1, 5, wdata, 777ULL);
    uint8_t rdata[16] = {0};
    oram_access(&oram, 0, 5, rdata, 888ULL);
    printf("Read: %s\n", rdata);
    oram_free(&oram);
    printf("OK\n");
    return 0;
}
