#include <stdio.h>
#include <string.h>
#include "tdx_amd.h"

int main(void) {
    printf("=== mini-trusted-compute — Intel TDX + AMD SEV Example ===\n\n");

    printf("--- Intel TDX Trust Domain ---\n");
    tdx_td_t td;
    if (tdx_td_init(&td, 256 * 1024 * 1024) != 0) {
        printf("FAILED: tdx_td_init\n");
        return 1;
    }
    printf("[OK] TD initialized with 256 MiB memory\n");

    if (tdx_td_create(&td) != 0) {
        printf("FAILED: tdx_td_create\n");
        return 1;
    }
    printf("[OK] TDH.MNG.CREATE executed\n");

    uint8_t firmware[4096];
    memset(firmware, 0xFD, sizeof(firmware));
    firmware[0] = 0x55; firmware[1] = 0xAA;
    if (tdx_td_build(&td, firmware, sizeof(firmware)) == 0)
        printf("[OK] Firmware loaded, initial measurement computed\n");

    for (int i = 0; i < 3; i++) {
        uint8_t chunk[TDX_HASH_SIZE];
        memset(chunk, 0xAB + i, sizeof(chunk));
        if (tdx_td_extend_mr(&td, chunk) == 0)
            printf("[OK] TDH.MR.EXTEND #%d\n", i + 1);
    }

    tdx_td_print_measurement(td.params.measurement);

    for (int i = 0; i < 4; i++) {
        uint64_t gpa = i * TDX_PAGE_SIZE;
        uint64_t hpa = 0x100000 + i * TDX_PAGE_SIZE;
        tdx_td_add_page(&td, gpa, hpa, 2,
                        TDX_PAGE_ATTRIBUTES_R | TDX_PAGE_ATTRIBUTES_W |
                        TDX_PAGE_ATTRIBUTES_X);
    }
    printf("[OK] 4 pages added to Secure EPT\n");

    tdx_vcpu_state_t vcpu;
    memset(&vcpu, 0, sizeof(vcpu));
    vcpu.rip = 0xFFFFF000;
    vcpu.rsp = 0x7F000000;
    vcpu.cr0 = 0x80000011;
    vcpu.cr3 = 0x1000;
    vcpu.cr4 = 0x000006A0;
    vcpu.efer = 0xD01;
    if (tdx_td_add_vcpu(&td, 0, &vcpu) == 0)
        printf("[OK] TDH.VP.CREATE: VCPU0 added\n");

    if (tdx_td_finalize(&td) == 0)
        printf("[OK] TDH.MR.FINALIZE: TD is RUNNING\n");

    tdx_td_info_t td_info;
    if (tdx_td_get_info(&td, &td_info) == 0)
        printf("[OK] TD info retrieved\n");

    uint64_t exit_reason;
    if (tdx_td_enter(&td, 0, &exit_reason) == 0)
        printf("[OK] TDH.VP.ENTER: VCPU0 entered\n");
    printf("     Exit reason: %llu\n", (unsigned long long)exit_reason);

    tdx_td_destroy(&td);
    printf("[OK] TD destroyed\n\n");

    printf("--- AMD SEV Virtual Machine ---\n");
    sev_vm_t vm;
    if (sev_vm_init(&vm, 512 * 1024 * 1024, true, false) != 0) {
        printf("FAILED: sev_vm_init\n");
        return 1;
    }
    printf("[OK] SEV-ES VM initialized with 512 MiB encrypted memory\n");

    if (sev_vm_launch_start(&vm, SEV_POLICY_ES | SEV_POLICY_NODBG) == 0)
        printf("[OK] LAUNCH_START: policy=ES|NODBG\n");

    uint8_t guest_code[8192];
    memset(guest_code, 0x90, sizeof(guest_code));
    guest_code[0] = 0xB8; guest_code[1] = 0x01; guest_code[2] = 0x00;
    guest_code[3] = 0x00; guest_code[4] = 0x00;

    uint64_t seg_size = 4096;
    for (uint64_t gpa = 0; gpa < sizeof(guest_code); gpa += seg_size) {
        uint64_t left = sizeof(guest_code) - gpa;
        uint64_t size = left < seg_size ? left : seg_size;
        if (sev_vm_launch_update(&vm, gpa, guest_code + gpa,
                                 size, 1 << 0) == 0)
            printf("[OK] LAUNCH_UPDATE: GPA=0x%llx size=%llu\n",
                   (unsigned long long)gpa, (unsigned long long)size);
    }

    uint8_t measurement[SEV_MEASUREMENT_SIZE];
    uint32_t meas_size;
    if (sev_vm_launch_measure(&vm, measurement, &meas_size) == 0) {
        printf("[OK] LAUNCH_MEASURE:\n    ");
        for (int i = 0; i < 8; i++) printf("%02x", measurement[i]);
        printf("...\n");
    }

    uint8_t secret[] = "SEV-injected-disc-secret";
    sev_vm_launch_secret(&vm, secret, (uint32_t)strlen((char *)secret) + 1);
    printf("[OK] LAUNCH_SECRET injected\n");

    if (sev_vm_launch_finish(&vm) == 0)
        printf("[OK] LAUNCH_FINISH: VM is now SEV-ES_RUNNING\n");

    if (sev_vm_activate(&vm) == 0)
        printf("[OK] ACTIVATE called\n");

    uint8_t nonce[32];
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(i * 7);
    sev_attest_report_t sev_report;
    if (sev_vm_attest(&vm, nonce, sizeof(nonce), &sev_report) == 0) {
        printf("[OK] SEV Attestation Report:\n");
        sev_vm_print_report(&sev_report);
    }

    if (sev_vm_deactivate(&vm) == 0)
        printf("[OK] DEACTIVATE: VM unencrypted\n");

    sev_vm_destroy(&vm);
    printf("[OK] SEV VM destroyed\n");

    printf("--- AMD SEV-SNP ---\n");
    sev_vm_t snp_vm;
    if (sev_vm_init(&snp_vm, 256 * 1024 * 1024, true, true) != 0) {
        printf("FAILED: sev_snp init\n");
        return 1;
    }
    printf("[OK] SEV-SNP VM initialized\n");

    sev_vm_launch_start(&snp_vm, SEV_POLICY_SNP | SEV_POLICY_NODBG);
    sev_vm_launch_update(&snp_vm, 0, guest_code, 4096, 1 << 0);
    sev_vm_launch_finish(&snp_vm);
    printf("[OK] SEV-SNP VM launched\n");

    sev_snp_attest_report_t snp_report;
    uint8_t snp_report_data[64];
    for (int i = 0; i < 64; i++) snp_report_data[i] = (uint8_t)(i * 3);
    if (sev_vm_snp_attest(&snp_vm, snp_report_data, sizeof(snp_report_data),
                          &snp_report) == 0) {
        printf("[OK] SEV-SNP Attestation Report generated\n");
        printf("    Version:     %u\n", snp_report.version);
        printf("    Guest Policy: 0x%llx\n",
               (unsigned long long)snp_report.guest_policy);
    }

    sev_vm_destroy(&snp_vm);
    printf("[OK] SEV-SNP VM destroyed\n");
    printf("\n[DONE] TDX + SEV examples complete.\n");
    return 0;
}
