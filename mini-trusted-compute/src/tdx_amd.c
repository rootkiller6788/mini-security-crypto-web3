#include "tdx_amd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static uint64_t tdx_align_page(uint64_t addr) {
    return (addr + TDX_PAGE_SIZE - 1) & ~(uint64_t)(TDX_PAGE_SIZE - 1);
}

static void tdx_hash384(const uint8_t *data, size_t len,
                        uint8_t digest[TDX_HASH_SIZE]) {
    (void)data;
    for (int i = 0; i < TDX_HASH_SIZE; i++)
        digest[i] = (uint8_t)((i + len) * 17 + 0xEF);
}

static void sev_hash384(const uint8_t *data, size_t len,
                        uint8_t digest[SEV_MEASUREMENT_SIZE]) {
    (void)data;
    for (int i = 0; i < SEV_MEASUREMENT_SIZE; i++)
        digest[i] = (uint8_t)((i + len + 1) * 23 + 0xCD);
}

int tdx_td_init(tdx_td_t *td, uint64_t size) {
    if (!td || size < TDX_PAGE_SIZE) return -1;
    memset(td, 0, sizeof(*td));
    td->params.td_size = tdx_align_page(size);
    td->memory_size = td->params.td_size;
    td->memory = (uint8_t *)calloc((size_t)td->memory_size, 1);
    if (!td->memory) return -1;
    td->sept_size = (td->memory_size / TDX_PAGE_SIZE) * 64;
    td->sept = (uint8_t *)calloc((size_t)td->sept_size, 1);
    if (!td->sept) { free(td->memory); return -1; }
    td->state = TDX_TD_UNINITIALIZED;
    td->vcpu_count = 0;
    td->debug = false;

    td->tdh_mng_create       = NULL;
    td->tdh_mng_key_config   = NULL;
    td->tdh_mng_init         = NULL;
    td->tdh_mem_page_add     = NULL;
    td->tdh_mem_page_aug     = NULL;
    td->tdh_mem_sept_add     = NULL;
    td->tdh_mr_extend        = NULL;
    td->tdh_mr_finalize      = NULL;
    td->tdh_vp_create        = NULL;
    td->tdh_vp_enter         = NULL;
    td->tdh_vp_flush         = NULL;
    td->tdh_mng_destroy      = NULL;
    td->tdh_mem_page_remove  = NULL;
    td->tdh_mem_range_block  = NULL;
    td->tdh_mem_track        = NULL;
    td->tdh_sys_rd           = NULL;
    td->tdh_phymem_page_rdmd = NULL;
    return 0;
}

int tdx_td_create(tdx_td_t *td) {
    if (!td || td->state != TDX_TD_UNINITIALIZED) return -1;
    memset(td->params.measurement, 0, TDX_MEASUREMENT_SIZE);
    td->params.td_attributes = 0;
    td->params.xfam = 0;
    td->params.td_base = 0;
    td->state = TDX_TD_INITIALIZED;
    return 0;
}

int tdx_td_build(tdx_td_t *td, const uint8_t *firmware, size_t fw_size) {
    if (!td || td->state != TDX_TD_INITIALIZED) return -1;
    if (!firmware || fw_size == 0) return -1;
    if (fw_size > td->memory_size) return -1;

    memcpy(td->memory, firmware, fw_size);

    uint8_t measurement_buf[TDX_PAGE_SIZE];
    memset(measurement_buf, 0, sizeof(measurement_buf));
    memcpy(measurement_buf, td->memory, fw_size < TDX_PAGE_SIZE ? fw_size : TDX_PAGE_SIZE);

    tdx_hash384(measurement_buf, TDX_PAGE_SIZE, td->params.measurement);
    memcpy(td->info.measurement, td->params.measurement, TDX_MEASUREMENT_SIZE);
    return 0;
}

int tdx_td_add_page(tdx_td_t *td, uint64_t gpa, uint64_t hpa,
                    uint64_t level, tdx_page_attrs_t attrs) {
    if (!td || td->state != TDX_TD_INITIALIZED) return -1;
    if (gpa >= td->memory_size) return -1;

    uint64_t page_idx = gpa / TDX_PAGE_SIZE;
    uint64_t sept_entry_idx = page_idx;
    if (sept_entry_idx * 16 < td->sept_size) {
        uint8_t *entry = td->sept + sept_entry_idx * 16;
        memcpy(entry, &hpa, 8);
        entry[8] = (uint8_t)level;
        entry[9] = (uint8_t)attrs;
    }
    return 0;
}

int tdx_td_extend_mr(tdx_td_t *td, const uint8_t data[TDX_HASH_SIZE]) {
    if (!td || td->state != TDX_TD_INITIALIZED) return -1;
    if (!data) return -1;

    uint8_t concat[TDX_HASH_SIZE * 2];
    memcpy(concat, td->params.measurement, TDX_HASH_SIZE);
    memcpy(concat + TDX_HASH_SIZE, data, TDX_HASH_SIZE);

    tdx_hash384(concat, TDX_HASH_SIZE * 2, td->params.measurement);
    memcpy(td->info.measurement, td->params.measurement, TDX_MEASUREMENT_SIZE);
    return 0;
}

int tdx_td_finalize(tdx_td_t *td) {
    if (!td || td->state != TDX_TD_INITIALIZED) return -1;
    td->state = TDX_TD_RUNNING;
    return 0;
}

int tdx_td_add_vcpu(tdx_td_t *td, uint32_t vcpu_id, tdx_vcpu_state_t *state) {
    if (!td || td->state != TDX_TD_INITIALIZED) return -1;
    if (vcpu_id >= 64) return -1;
    if (state) memcpy(&td->vcpu[vcpu_id], state, sizeof(*state));
    else memset(&td->vcpu[vcpu_id], 0, sizeof(tdx_vcpu_state_t));
    if (vcpu_id >= td->vcpu_count) td->vcpu_count = vcpu_id + 1;
    return 0;
}

int tdx_td_enter(tdx_td_t *td, uint32_t vcpu_id, uint64_t *exit_reason) {
    if (!td || td->state != TDX_TD_RUNNING) return -1;
    if (vcpu_id >= td->vcpu_count) return -1;
    if (exit_reason) *exit_reason = 0;
    return 0;
}

int tdx_td_destroy(tdx_td_t *td) {
    if (!td) return -1;
    td->state = TDX_TD_DESTROYED;
    free(td->memory);  td->memory = NULL;
    free(td->sept);    td->sept = NULL;
    td->memory_size = 0;
    td->sept_size = 0;
    return 0;
}

int tdx_td_get_info(tdx_td_t *td, tdx_td_info_t *info) {
    if (!td || !info) return -1;
    memcpy(info, &td->info, sizeof(*info));
    return 0;
}

int tdx_seam_call_execute(uint32_t leaf, tdx_seam_call_t *call) {
    (void)leaf;
    if (!call) return -1;
    call->error_code = 0;
    return 0;
}

void tdx_td_print_measurement(const uint8_t measurement[TDX_MEASUREMENT_SIZE]) {
    if (!measurement) return;
    printf("TD Measurement: ");
    for (int i = 0; i < TDX_MEASUREMENT_SIZE; i++)
        printf("%02x", measurement[i]);
    printf("\n");
}

int sev_vm_init(sev_vm_t *vm, uint64_t memory_size, bool es, bool snp) {
    if (!vm || memory_size < SEV_PAGE_SIZE) return -1;
    memset(vm, 0, sizeof(*vm));
    vm->memory_size = tdx_align_page(memory_size);
    vm->encrypted_memory = (uint8_t *)calloc((size_t)vm->memory_size, 1);
    if (!vm->encrypted_memory) return -1;
    vm->es_enabled = es;
    vm->snp_enabled = snp;
    vm->asid = 1;
    vm->state = SEV_STATE_UNENCRYPTED;

    vm->launch_start     = NULL;
    vm->launch_update    = NULL;
    vm->launch_measure   = NULL;
    vm->launch_secret    = NULL;
    vm->launch_finish    = NULL;
    vm->send_start       = NULL;
    vm->receive_start    = NULL;
    vm->attestation      = NULL;
    vm->snp_attestation  = NULL;
    vm->activate         = NULL;
    vm->deactivate       = NULL;
    vm->guest_status     = NULL;
    return 0;
}

int sev_vm_launch_start(sev_vm_t *vm, uint32_t policy) {
    if (!vm || vm->state != SEV_STATE_UNENCRYPTED) return -1;
    vm->config.policy = policy;
    vm->state = SEV_STATE_LAUNCHING;
    return 0;
}

int sev_vm_launch_update(sev_vm_t *vm, uint64_t gpa, const uint8_t *data,
                         uint64_t size, uint8_t page_type) {
    if (!vm || vm->state != SEV_STATE_LAUNCHING) return -1;
    if (!data || size == 0) return -1;
    if (gpa + size > vm->memory_size) return -1;

    memcpy(vm->encrypted_memory + gpa, data, (size_t)size);

    uint8_t hash_input[128];
    memset(hash_input, 0, sizeof(hash_input));
    hash_input[0] = page_type;
    memcpy(hash_input + 1, data, (size_t)(size < 127 ? size : 127));

    uint8_t digest[SEV_MEASUREMENT_SIZE];
    sev_hash384(hash_input, 128, digest);

    for (int i = 0; i < SEV_MEASUREMENT_SIZE; i++)
        vm->config.measurement[i] ^= digest[i];

    return 0;
}

int sev_vm_launch_measure(sev_vm_t *vm, uint8_t *measurement, uint32_t *size) {
    if (!vm || !measurement || !size) return -1;
    *size = SEV_MEASUREMENT_SIZE;
    memcpy(measurement, vm->config.measurement, SEV_MEASUREMENT_SIZE);
    return 0;
}

int sev_vm_launch_finish(sev_vm_t *vm) {
    if (!vm || vm->state != SEV_STATE_LAUNCHING) return -1;
    if (vm->snp_enabled) vm->state = SEV_STATE_SNP_RUNNING;
    else if (vm->es_enabled) vm->state = SEV_STATE_ES_RUNNING;
    else vm->state = SEV_STATE_RUNNING;
    return 0;
}

int sev_vm_launch_secret(sev_vm_t *vm, const uint8_t *secret, uint32_t size) {
    if (!vm || vm->state != SEV_STATE_LAUNCHING) return -1;
    if (!secret || size == 0 || size > 64) return -1;
    if (vm->state == SEV_STATE_LAUNCHING) vm->state = SEV_STATE_LAUNCH_SECRET;
    return 0;
}

int sev_vm_activate(sev_vm_t *vm) {
    if (!vm) return -1;
    return 0;
}

int sev_vm_attest(sev_vm_t *vm, const uint8_t *nonce, uint32_t nonce_size,
                  sev_attest_report_t *report) {
    if (!vm || !report) return -1;
    memset(report, 0, sizeof(*report));
    report->version = 1;
    report->guest_svn = 0;
    memcpy(report->policy, &vm->config.policy, SEV_POLICY_SIZE);
    memcpy(report->measurement, vm->config.measurement, SEV_MEASUREMENT_SIZE);
    if (nonce && nonce_size > 0)
        memcpy(report->host_data, nonce, nonce_size < 32 ? nonce_size : 32);
    return 0;
}

int sev_vm_snp_attest(sev_vm_t *vm, const uint8_t *report_data,
                      uint32_t report_data_size,
                      sev_snp_attest_report_t *report) {
    if (!vm || !report) return -1;
    memset(report, 0, sizeof(*report));
    report->version = 1;
    report->guest_policy = vm->config.policy;
    memcpy(report->measurement, vm->config.measurement, SEV_MEASUREMENT_SIZE);
    memset(report->vmpl, 0, 4);
    memset(report->entry_vmpl, 0, 4);
    if (report_data && report_data_size > 0)
        memcpy(report->measurement + 16, report_data,
               report_data_size < 32 ? report_data_size : 32);
    memset(report->reported_tcb, 0x01, 8);
    memset(report->launch_tcb, 0x01, 8);
    return 0;
}

int sev_vm_deactivate(sev_vm_t *vm) {
    if (!vm) return -1;
    vm->state = SEV_STATE_UNENCRYPTED;
    return 0;
}

int sev_vm_destroy(sev_vm_t *vm) {
    if (!vm) return -1;
    vm->state = SEV_STATE_DESTROYED;
    free(vm->encrypted_memory);
    vm->encrypted_memory = NULL;
    vm->memory_size = 0;
    return 0;
}

void sev_vm_print_report(const sev_attest_report_t *report) {
    if (!report) return;
    printf("SEV Attestation Report:\n");
    printf("  Version:       %u\n", report->version);
    printf("  Guest SVN:     %u\n", report->guest_svn);
    printf("  Measurement:   ");
    for (int i = 0; i < 8; i++) printf("%02x", report->measurement[i]);
    printf("...\n");
    printf("  Policy:        ");
    for (int i = 0; i < SEV_POLICY_SIZE; i++) printf("%02x", report->policy[i]);
    printf("\n");
}
