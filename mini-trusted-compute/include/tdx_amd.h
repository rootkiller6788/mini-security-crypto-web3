#ifndef MINI_TDX_AMD_H
#define MINI_TDX_AMD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TDX_PAGE_SIZE             4096
#define TDX_MEASUREMENT_SIZE      48
#define TDX_MK_SIZE               32
#define TDX_SEAM_CALL_VECTOR_SIZE 64
#define TDX_VMCALL_LEAF_MAX       256
#define TDX_REPORT_SIZE           1024
#define TDX_HASH_SIZE             48
#define TDX_NONCE_SIZE            32
#define TDX_TD_INFO_SIZE          512
#define TDX_QUOTE_SIZE            8192

#define SEV_PAGE_SIZE             4096
#define SEV_MEASUREMENT_SIZE      48
#define SEV_POLICY_SIZE           4
#define SEV_ES_CPUID_MAX          64
#define SEV_SNP_ID_BLOCK_SIZE      96
#define SEV_SNP_ID_AUTH_SIZE      4096
#define SEV_ATTEST_REPORT_SIZE    1184
#define SEV_SNP_VCEK_SIZE         2048

typedef enum {
    TDX_TD_UNINITIALIZED = 0,
    TDX_TD_INITIALIZED   = 1,
    TDX_TD_RUNNING       = 2,
    TDX_TD_PAUSED        = 3,
    TDX_TD_DESTROYED     = 4
} tdx_td_state_t;

typedef enum {
    TDX_PAGE_ATTRIBUTES_R  = 0x01,
    TDX_PAGE_ATTRIBUTES_W  = 0x02,
    TDX_PAGE_ATTRIBUTES_X  = 0x04,
    TDX_PAGE_ATTRIBUTES_O  = 0x08,
    TDX_PAGE_ATTRIBUTES_VD = 0x10,
    TDX_PAGE_ATTRIBUTES_SW = 0x20
} tdx_page_attrs_t;

typedef enum {
    SEV_STATE_UNENCRYPTED  = 0,
    SEV_STATE_LAUNCHING    = 1,
    SEV_STATE_LAUNCH_SECRET = 2,
    SEV_STATE_RUNNING      = 3,
    SEV_STATE_ES_RUNNING   = 4,
    SEV_STATE_SNP_RUNNING  = 5,
    SEV_STATE_SENDING      = 6,
    SEV_STATE_RECEIVING    = 7,
    SEV_STATE_DESTROYED    = 8
} sev_vm_state_t;

typedef enum {
    SEV_POLICY_NODBG     = 0x01,
    SEV_POLICY_NOKS      = 0x02,
    SEV_POLICY_ES        = 0x04,
    SEV_POLICY_NOSEND    = 0x08,
    SEV_POLICY_DOMAIN    = 0x10,
    SEV_POLICY_SEV       = 0x20,
    SEV_POLICY_SNP       = 0x40,
    SEV_POLICY_MASK      = 0x7F
} sev_policy_flags_t;

typedef enum {
    TDX_SEAM_CALL_TDH_MNG_INIT          = 0x0000,
    TDX_SEAM_CALL_TDH_MNG_KEY_CONFIG    = 0x0001,
    TDX_SEAM_CALL_TDH_MNG_CREATE        = 0x0002,
    TDX_SEAM_CALL_TDH_MNG_ADDCX         = 0x0003,
    TDX_SEAM_CALL_TDH_MNG_INIT_FINAL    = 0x0004,
    TDX_SEAM_CALL_TDH_PHYMEM_PAGE_RDMD  = 0x0005,
    TDX_SEAM_CALL_TDH_MEM_PAGE_ADD      = 0x0006,
    TDX_SEAM_CALL_TDH_MEM_PAGE_AUG      = 0x0007,
    TDX_SEAM_CALL_TDH_MEM_PAGE_REMOVE   = 0x0008,
    TDX_SEAM_CALL_TDH_MEM_PAGE_RELOCATE = 0x0009,
    TDX_SEAM_CALL_TDH_MEM_SEPT_ADD      = 0x000A,
    TDX_SEAM_CALL_TDH_MEM_SEPT_REMOVE   = 0x000B,
    TDX_SEAM_CALL_TDH_VP_ENTER          = 0x000C,
    TDX_SEAM_CALL_TDH_VP_FLUSH          = 0x000D,
    TDX_SEAM_CALL_TDH_VP_INVLD          = 0x000E,
    TDX_SEAM_CALL_TDH_MNG_KEY_RECLAIM   = 0x000F,
    TDX_SEAM_CALL_TDH_MEM_TRACK         = 0x0010,
    TDX_SEAM_CALL_TDH_MEM_RANGE_BLOCK   = 0x0011,
    TDX_SEAM_CALL_TDH_MNG_VPFLUSHDONE   = 0x0012,
    TDX_SEAM_CALL_TDH_MNG_DESTROY       = 0x0013,
    TDX_SEAM_CALL_TDH_MEM_PAGE_PROMOTE  = 0x0014,
    TDX_SEAM_CALL_TDH_MEM_PAGE_DEMOTE   = 0x0015,
    TDX_SEAM_CALL_TDH_SYS_RD            = 0x0016,
    TDX_SEAM_CALL_TDH_SYS_CONFIG        = 0x0017,
    TDX_SEAM_CALL_TDH_MR_EXTEND         = 0x0018,
    TDX_SEAM_CALL_TDH_MR_FINALIZE       = 0x0019,
    TDX_SEAM_CALL_TDH_VP_CREATE         = 0x001A,
    TDX_SEAM_CALL_TDH_VP_INIT           = 0x001B
} tdx_seam_leaf_t;

#pragma pack(push, 1)

typedef struct {
    uint8_t  measurement[TDX_MEASUREMENT_SIZE];
    uint8_t  mk_td_key[TDX_MK_SIZE];
    uint64_t td_attributes;
    uint32_t xfam;
    uint32_t reserved;
    uint64_t td_base;
    uint64_t td_size;
} tdx_td_params_t;

typedef struct {
    uint8_t  measurement[TDX_MEASUREMENT_SIZE];
    uint8_t  mr_config_id[TDX_HASH_SIZE];
    uint8_t  mr_owner[TDX_HASH_SIZE];
    uint8_t  mr_owner_config[TDX_HASH_SIZE];
    uint64_t attributes[4];
    uint8_t  rt_mr0[TDX_HASH_SIZE];
    uint8_t  rt_mr1[TDX_HASH_SIZE];
    uint8_t  rt_mr2[TDX_HASH_SIZE];
    uint8_t  rt_mr3[TDX_HASH_SIZE];
    uint64_t tdvf_mr;
    uint8_t  servtd_hash[TDX_HASH_SIZE];
} tdx_td_info_t;

typedef struct {
    uint32_t seam_call_id;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t error_code;
    uint64_t reserved[4];
} tdx_seam_call_t;

typedef struct {
    uint8_t  gpa_page[16];
    uint8_t  hpa_page[16];
    uint64_t level;
    uint32_t attributes;
    uint32_t reserved;
} tdx_sept_entry_t;

typedef struct {
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;
    uint64_t sysenter_cs;
    uint64_t sysenter_eip;
    uint64_t sysenter_esp;
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t kernel_gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
    uint64_t ss;
    uint64_t tr;
    uint64_t ldtr;
    uint64_t gdtr[2];
    uint64_t idtr[2];
    uint64_t efer;
    uint8_t  fpu[512];
    uint64_t pending_event;
    uint64_t vmfunc;
    uint64_t eptp;
} tdx_vcpu_state_t;

typedef struct {
    uint32_t version;
    uint32_t guest_svn;
    uint8_t  policy[SEV_POLICY_SIZE];
    uint8_t  measurement[SEV_MEASUREMENT_SIZE];
    uint8_t  host_data[32];
    uint8_t  id_key_digest[48];
    uint8_t  id_auth_digest[48];
    uint8_t  key_share[32];
    uint8_t  author_key_digest[48];
    uint8_t  report_id[32];
    uint8_t  report_id_ma[32];
    uint8_t  chip_id[64];
    uint32_t reported_tcb;
    uint32_t reserved;
    uint8_t  signature[512];
    uint8_t  cert_chain[2048];
    uint32_t cert_chain_size;
} sev_attest_report_t;

typedef struct {
    uint8_t  measurement[SEV_MEASUREMENT_SIZE];
    uint64_t policy;
    uint32_t api_major;
    uint32_t api_minor;
    uint32_t build_id;
    uint32_t policy_flags;
    uint8_t  owner_key[48];
    uint8_t  guest_handle[16];
    uint8_t  es_teek[32];
    uint8_t  es_teeh[32];
    uint8_t  snp_id_block[SEV_SNP_ID_BLOCK_SIZE];
    uint8_t  snp_id_auth[SEV_SNP_ID_AUTH_SIZE];
    uint32_t snp_id_auth_size;
    uint8_t  vmpck0[32];
    uint8_t  vmpck1[32];
    uint8_t  vmpck2[32];
    uint8_t  vmpck3[32];
    uint8_t  vcek_cert[SEV_SNP_VCEK_SIZE];
    uint32_t vcek_cert_size;
} sev_vm_config_t;

typedef struct {
    uint8_t  vmpl[4];
    uint8_t  entry_vmpl[4];
    uint8_t  permissions_mask[8];
    uint8_t  measurement[SEV_MEASUREMENT_SIZE];
    uint8_t  id_block_digest[48];
    uint8_t  author_key_digest[48];
    uint64_t guest_features;
    uint64_t guest_policy;
    uint64_t vtom;
    uint8_t  family_id[16];
    uint8_t  image_id[16];
    uint32_t version;
    uint32_t reserved;
    uint8_t  commited_svn[16];
    uint8_t  current_svn[16];
    uint8_t  reported_tcb[8];
    uint8_t  launch_tcb[8];
    uint8_t  signature_r[72];
    uint8_t  signature_s[72];
    uint8_t  chip_id[64];
} sev_snp_attest_report_t;

#pragma pack(pop)

typedef struct tdx_td_s {
    tdx_td_params_t     params;
    tdx_td_info_t       info;
    tdx_td_state_t      state;
    tdx_vcpu_state_t    vcpu[64];
    uint32_t            vcpu_count;
    uint8_t            *memory;
    uint64_t            memory_size;
    uint8_t            *sept;
    uint64_t            sept_size;
    uint8_t             mk_td_key[TDX_MK_SIZE];
    bool                debug;

    int (*tdh_mng_create)(struct tdx_td_s *td);
    int (*tdh_mng_key_config)(struct tdx_td_s *td);
    int (*tdh_mng_init)(struct tdx_td_s *td);
    int (*tdh_mem_page_add)(struct tdx_td_s *td, uint64_t gpa, uint64_t source_hpa,
                            uint64_t level, tdx_page_attrs_t attrs);
    int (*tdh_mem_page_aug)(struct tdx_td_s *td, uint64_t gpa, uint64_t hpa,
                            uint64_t level, tdx_page_attrs_t attrs);
    int (*tdh_mem_sept_add)(struct tdx_td_s *td, uint64_t gpa, uint64_t hpa,
                            tdx_page_attrs_t attrs);
    int (*tdh_mr_extend)(struct tdx_td_s *td, const uint8_t data[TDX_HASH_SIZE]);
    int (*tdh_mr_finalize)(struct tdx_td_s *td);
    int (*tdh_vp_create)(struct tdx_td_s *td, uint32_t vcpu_id,
                         tdx_vcpu_state_t *state);
    int (*tdh_vp_enter)(struct tdx_td_s *td, uint32_t vcpu_id,
                        uint64_t *exit_reason);
    int (*tdh_vp_flush)(struct tdx_td_s *td, uint32_t vcpu_id);
    int (*tdh_mng_destroy)(struct tdx_td_s *td);
    int (*tdh_mem_page_remove)(struct tdx_td_s *td, uint64_t gpa, uint64_t level);
    int (*tdh_mem_range_block)(struct tdx_td_s *td, uint64_t gpa, uint64_t pages);
    int (*tdh_mem_track)(struct tdx_td_s *td, uint64_t gpa);
    int (*tdh_sys_rd)(uint64_t *global_metadata);
    int (*tdh_phymem_page_rdmd)(uint64_t *hpa, uint64_t *level,
                                tdx_page_attrs_t *attrs);
} tdx_td_t;

typedef struct sev_vm_s {
    sev_vm_config_t       config;
    sev_vm_state_t        state;
    uint8_t              *encrypted_memory;
    uint64_t              memory_size;
    uint32_t              asid;
    uint32_t              handle;
    bool                  es_enabled;
    bool                  snp_enabled;
    uint8_t               vcek_cert[SEV_SNP_VCEK_SIZE];
    uint32_t              vcek_cert_size;

    int (*launch_start)(struct sev_vm_s *vm, uint32_t policy, uint8_t *cert_chain,
                        uint32_t cert_size, uint8_t *session,
                        uint32_t session_size);
    int (*launch_update)(struct sev_vm_s *vm, uint64_t gpa, const uint8_t *data,
                         uint64_t size, uint8_t page_type);
    int (*launch_measure)(struct sev_vm_s *vm, uint8_t *measurement, uint32_t *size);
    int (*launch_secret)(struct sev_vm_s *vm, const uint8_t *secret, uint32_t size,
                         uint32_t header_flags, uint8_t *header,
                         uint32_t header_size);
    int (*launch_finish)(struct sev_vm_s *vm);
    int (*send_start)(struct sev_vm_s *vm, uint32_t policy, uint8_t *cert_chain,
                      uint32_t cert_size, uint8_t *session,
                      uint32_t session_size);
    int (*receive_start)(struct sev_vm_s *vm, uint32_t policy, uint8_t *session,
                         uint32_t session_size, uint8_t *incoming_data,
                         uint32_t data_size);
    int (*attestation)(struct sev_vm_s *vm, const uint8_t *nonce, uint32_t nonce_size,
                       sev_attest_report_t *report);
    int (*snp_attestation)(struct sev_vm_s *vm, const uint8_t *report_data,
                           uint32_t report_data_size,
                           sev_snp_attest_report_t *report);
    int (*activate)(struct sev_vm_s *vm);
    int (*deactivate)(struct sev_vm_s *vm);
    int (*guest_status)(struct sev_vm_s *vm, uint32_t *status);
} sev_vm_t;

int  tdx_td_init(tdx_td_t *td, uint64_t size);
int  tdx_td_create(tdx_td_t *td);
int  tdx_td_build(tdx_td_t *td, const uint8_t *firmware, size_t fw_size);
int  tdx_td_add_page(tdx_td_t *td, uint64_t gpa, uint64_t hpa,
                     uint64_t level, tdx_page_attrs_t attrs);
int  tdx_td_extend_mr(tdx_td_t *td, const uint8_t data[TDX_HASH_SIZE]);
int  tdx_td_finalize(tdx_td_t *td);
int  tdx_td_add_vcpu(tdx_td_t *td, uint32_t vcpu_id, tdx_vcpu_state_t *state);
int  tdx_td_enter(tdx_td_t *td, uint32_t vcpu_id, uint64_t *exit_reason);
int  tdx_td_destroy(tdx_td_t *td);
int  tdx_td_get_info(tdx_td_t *td, tdx_td_info_t *info);
int  tdx_seam_call_execute(uint32_t leaf, tdx_seam_call_t *call);
void tdx_td_print_measurement(const uint8_t measurement[TDX_MEASUREMENT_SIZE]);

int  sev_vm_init(sev_vm_t *vm, uint64_t memory_size, bool es, bool snp);
int  sev_vm_launch_start(sev_vm_t *vm, uint32_t policy);
int  sev_vm_launch_update(sev_vm_t *vm, uint64_t gpa, const uint8_t *data,
                          uint64_t size, uint8_t page_type);
int  sev_vm_launch_measure(sev_vm_t *vm, uint8_t *measurement, uint32_t *size);
int  sev_vm_launch_finish(sev_vm_t *vm);
int  sev_vm_launch_secret(sev_vm_t *vm, const uint8_t *secret, uint32_t size);
int  sev_vm_activate(sev_vm_t *vm);
int  sev_vm_attest(sev_vm_t *vm, const uint8_t *nonce, uint32_t nonce_size,
                   sev_attest_report_t *report);
int  sev_vm_snp_attest(sev_vm_t *vm, const uint8_t *report_data,
                       uint32_t report_data_size,
                       sev_snp_attest_report_t *report);
int  sev_vm_deactivate(sev_vm_t *vm);
int  sev_vm_destroy(sev_vm_t *vm);
void sev_vm_print_report(const sev_attest_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* MINI_TDX_AMD_H */
