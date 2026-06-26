#ifndef CONTAINER_SECURITY_H
#define CONTAINER_SECURITY_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define CS_MAX_IMAGES          256
#define CS_MAX_VULNS          1024
#define CS_MAX_SECCOMP_RULES   128
#define CS_MAX_APPARMOR_RULES  128
#define CS_MAX_CAPABILITIES     64
#define CS_MAX_NETWORK_POLICIES 64
#define CS_MAX_SECRETS         256
#define CS_MAX_SIGNERS          32
#define CS_PATH_LEN            512
#define CS_NAME_LEN            256
#define CS_DIGEST_LEN          128
#define CS_SIG_LEN            1024

typedef enum {
    CS_SEVERITY_CRITICAL  = 0,
    CS_SEVERITY_HIGH      = 1,
    CS_SEVERITY_MEDIUM    = 2,
    CS_SEVERITY_LOW       = 3,
    CS_SEVERITY_INFO      = 4
} cs_severity_t;

typedef enum {
    CS_POD_PRIVILEGED   = 0,
    CS_POD_BASELINE     = 1,
    CS_POD_RESTRICTED   = 2
} cs_pod_security_level_t;

typedef enum {
    CS_RUNTIME_SECCOMP  = 0,
    CS_RUNTIME_APPARMOR = 1,
    CS_RUNTIME_SELINUX  = 2
} cs_runtime_profile_t;

typedef enum {
    CS_INGRESS = 0,
    CS_EGRESS  = 1
} cs_policy_direction_t;

typedef enum {
    CS_SIGNATURE_COSIGN    = 0,
    CS_SIGNATURE_NOTARY    = 1,
    CS_SIGNATURE_GPG       = 2
} cs_signature_type_t;

typedef struct {
    char  cve_id[32];
    char  package_name[CS_NAME_LEN];
    char  installed_version[64];
    char  fixed_version[64];
    cs_severity_t severity;
    float cvss_score;
    char  description[512];
    int   fix_available;
} cs_vulnerability_t;

typedef struct {
    char  name[CS_NAME_LEN];
    int   id;
    char  syscall_names[CS_MAX_SECCOMP_RULES][64];
    int   syscall_count;
    char  default_action[16];
    int   architecture;
} cs_seccomp_profile_t;

typedef struct {
    char  name[CS_NAME_LEN];
    char  rules[CS_MAX_APPARMOR_RULES][CS_PATH_LEN];
    int   rule_count;
    char  profile_mode[16];
} cs_apparmor_profile_t;

typedef struct {
    char              image_name[CS_NAME_LEN];
    char              image_tag[64];
    char              image_digest[CS_DIGEST_LEN];
    cs_vulnerability_t vulnerabilities[CS_MAX_VULNS];
    int               vuln_count;
    int               malware_detected;
    char              malware_detail[256];
    int               scan_pass;
    time_t            last_scan;
    int               size_bytes;
    int               layer_count;
    unsigned char     read_only_rootfs;
    unsigned char     run_as_non_root;
    unsigned char     drop_all_capabilities;
    int               added_capabilities[CS_MAX_CAPABILITIES];
    int               cap_count;
    unsigned char     no_new_privileges;
    int               uid;
    int               gid;
} cs_image_t;

typedef struct {
    char  name[CS_NAME_LEN];
    int   id;
    cs_policy_direction_t direction;
    char  from_namespace[CS_NAME_LEN];
    char  to_namespace[CS_NAME_LEN];
    int   from_port;
    int   to_port;
    char  protocol[8];
    unsigned char allow;
    char  cidr[45];
} cs_network_policy_t;

typedef struct {
    char    name[CS_NAME_LEN];
    char    namespace[CS_NAME_LEN];
    cs_pod_security_level_t pod_security_level;
    char    image_name[CS_NAME_LEN];
    char    seccomp_profile[CS_NAME_LEN];
    char    apparmor_profile[CS_NAME_LEN];
    char    selinux_label[CS_NAME_LEN];
    unsigned char privileged;
    unsigned char host_network;
    unsigned char host_pid;
    unsigned char host_ipc;
    unsigned char read_only_rootfs;
    unsigned char run_as_non_root;
    unsigned char allow_privilege_escalation;
    int     added_capabilities[CS_MAX_CAPABILITIES];
    int     cap_count;
    int     uid;
    int     gid;
    int     network_policy_ids[CS_MAX_NETWORK_POLICIES];
    int     network_policy_count;
    char    secret_names[CS_MAX_SECRETS][CS_NAME_LEN];
    int     secret_count;
    char    signed_by[CS_MAX_SIGNERS][CS_NAME_LEN];
    int     signer_count;
    cs_signature_type_t sig_type;
} cs_container_t;

typedef struct {
    cs_image_t            images[CS_MAX_IMAGES];
    int                   image_count;
    cs_network_policy_t   network_policies[CS_MAX_NETWORK_POLICIES];
    int                   network_policy_count;
    cs_seccomp_profile_t  seccomp_profiles[CS_MAX_SECCOMP_RULES];
    int                   seccomp_count;
    cs_apparmor_profile_t apparmor_profiles[CS_MAX_APPARMOR_RULES];
    int                   apparmor_count;
    int                   privileged_containers;
    int                   scanned_images;
    int                   failed_scans;
    int                   blocked_deployments;
} cs_state_t;

cs_image_t*       cs_scan_image(const char *name, const char *tag);
void              cs_add_vulnerability(cs_image_t *img, const char *cve,
                                        const char *package, cs_severity_t sev,
                                        float cvss, int fix_available);
int               cs_has_critical_vulns(const cs_image_t *img);
int               cs_count_severity(const cs_image_t *img, cs_severity_t sev);
int               cs_image_has_malware(const cs_image_t *img);
void              cs_set_malware(cs_image_t *img, const char *detail);
void              cs_set_readonly_rootfs(cs_image_t *img, int val);
void              cs_set_run_as_non_root(cs_image_t *img, int val);
void              cs_add_capability(cs_image_t *img, int cap_id);

cs_seccomp_profile_t*  cs_create_seccomp_profile(const char *name,
                                                   const char *default_action);
void                   cs_seccomp_add_syscall(cs_seccomp_profile_t *p,
                                               const char *syscall_name);
void                   cs_seccomp_block_all(cs_seccomp_profile_t *p);
void                   cs_seccomp_allow_network(cs_seccomp_profile_t *p);
void                   cs_seccomp_allow_filesystem(cs_seccomp_profile_t *p);

cs_apparmor_profile_t* cs_create_apparmor_profile(const char *name,
                                                    const char *mode);
void                   cs_apparmor_add_rule(cs_apparmor_profile_t *p,
                                             const char *rule);
void                   cs_apparmor_default_docker(cs_apparmor_profile_t *p);

int               cs_check_privileged(const cs_container_t *c);
int               cs_check_host_network(const cs_container_t *c);
int               cs_check_host_pid(const cs_container_t *c);
cs_pod_security_level_t cs_validate_pod_security(const cs_container_t *c);
const char*       cs_pod_security_violations(const cs_container_t *c,
                                              cs_pod_security_level_t target);

cs_network_policy_t* cs_create_network_policy(const char *name,
                                               cs_policy_direction_t dir,
                                               int allow);
void                cs_network_policy_set_namespace(cs_network_policy_t *np,
                                                     const char *from,
                                                     const char *to);
void                cs_network_policy_set_port(cs_network_policy_t *np,
                                                int from_port, int to_port,
                                                const char *protocol);
void                cs_network_policy_set_cidr(cs_network_policy_t *np,
                                                const char *cidr);
int                 cs_validate_network_policy(const cs_network_policy_t *np);
int                 cs_evaluate_network_policy(const cs_network_policy_t *np,
                                                const char *from_ns,
                                                const char *to_ns,
                                                int port,
                                                const char *direction);

void              cs_add_secret_to_container(cs_container_t *c,
                                              const char *secret_name);
int               cs_check_external_secrets(const cs_container_t *c);

int               cs_sign_image(cs_image_t *img, cs_signature_type_t type,
                                 const char *signer_name);
int               cs_verify_image_signature(const cs_image_t *img,
                                             const char *signer_name);
int               cs_verify_cosign(const cs_image_t *img,
                                    const char *public_key);

void              cs_init_state(cs_state_t *state);
const char*       cs_severity_name(cs_severity_t s);
const char*       cs_pod_level_name(cs_pod_security_level_t level);
void              cs_print_scan_report(const cs_image_t *img);
void              cs_print_container_report(const cs_container_t *c);
void              cs_print_summary(const cs_state_t *state);

#endif
