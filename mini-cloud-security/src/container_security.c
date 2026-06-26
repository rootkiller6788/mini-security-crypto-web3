#include "container_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) ((void)(x))

cs_image_t* cs_scan_image(const char *name, const char *tag) {
    cs_image_t *img = calloc(1, sizeof(cs_image_t));
    if (!img) return NULL;
    if (name) strncpy(img->image_name, name, CS_NAME_LEN - 1);
    if (tag) strncpy(img->image_tag, tag, 63);
    snprintf(img->image_digest, CS_DIGEST_LEN, "sha256:%016lx%016lx",
             (unsigned long)time(NULL), (unsigned long)(size_t)img);
    img->last_scan = time(NULL);
    img->run_as_non_root = 1;
    img->drop_all_capabilities = 1;
    img->no_new_privileges = 1;

    cs_add_vulnerability(img, "CVE-2023-44487", "libcurl4", CS_SEVERITY_HIGH, 7.5f, 1);
    cs_add_vulnerability(img, "CVE-2023-38545", "libcurl4", CS_SEVERITY_HIGH, 8.8f, 1);
    cs_add_vulnerability(img, "CVE-2023-5363", "openssl", CS_SEVERITY_HIGH, 7.4f, 1);
    cs_add_vulnerability(img, "CVE-2023-0464", "glibc", CS_SEVERITY_MEDIUM, 5.3f, 1);
    cs_add_vulnerability(img, "CVE-2023-4911", "glibc", CS_SEVERITY_HIGH, 7.8f, 1);
    cs_add_vulnerability(img, "CVE-2023-4807", "openssl", CS_SEVERITY_MEDIUM, 5.5f, 1);
    cs_add_vulnerability(img, "CVE-2024-21626", "runc", CS_SEVERITY_CRITICAL, 8.6f, 1);

    img->scan_pass = (img->vuln_count > 0) ? 0 : 1;
    img->size_bytes = 245 * 1024 * 1024;
    img->layer_count = 7;
    return img;
}

void cs_add_vulnerability(cs_image_t *img, const char *cve,
                           const char *package, cs_severity_t sev,
                           float cvss, int fix_available) {
    if (!img || img->vuln_count >= CS_MAX_VULNS) return;
    cs_vulnerability_t *v = &img->vulnerabilities[img->vuln_count++];
    memset(v, 0, sizeof(cs_vulnerability_t));
    if (cve) strncpy(v->cve_id, cve, 31);
    if (package) strncpy(v->package_name, package, CS_NAME_LEN - 1);
    v->severity = sev;
    v->cvss_score = cvss;
    v->fix_available = fix_available;
    snprintf(v->installed_version, 63, "1.%d.0", (int)(cvss * 10) % 10);
    snprintf(v->fixed_version, 63, "1.%d.1", (int)(cvss * 10) % 10);
    snprintf(v->description, 511, "Vulnerability in %s (packaged: %s), CVSS %.1f",
             package, cve, cvss);
}

int cs_has_critical_vulns(const cs_image_t *img) {
    return img ? cs_count_severity(img, CS_SEVERITY_CRITICAL) > 0 : 0;
}

int cs_count_severity(const cs_image_t *img, cs_severity_t sev) {
    if (!img) return 0;
    int count = 0;
    for (int i = 0; i < img->vuln_count; i++) {
        if (img->vulnerabilities[i].severity == sev) count++;
    }
    return count;
}

int cs_image_has_malware(const cs_image_t *img) {
    return img ? img->malware_detected : 0;
}

void cs_set_malware(cs_image_t *img, const char *detail) {
    if (!img) return;
    img->malware_detected = 1;
    if (detail) strncpy(img->malware_detail, detail, 255);
    img->scan_pass = 0;
}

void cs_set_readonly_rootfs(cs_image_t *img, int val) {
    if (img) img->read_only_rootfs = (unsigned char)(val ? 1 : 0);
}

void cs_set_run_as_non_root(cs_image_t *img, int val) {
    if (img) img->run_as_non_root = (unsigned char)(val ? 1 : 0);
}

void cs_add_capability(cs_image_t *img, int cap_id) {
    if (!img || img->cap_count >= CS_MAX_CAPABILITIES) return;
    img->added_capabilities[img->cap_count++] = cap_id;
}

cs_seccomp_profile_t* cs_create_seccomp_profile(const char *name,
                                                  const char *default_action) {
    cs_seccomp_profile_t *p = calloc(1, sizeof(cs_seccomp_profile_t));
    if (!p) return NULL;
    if (name) strncpy(p->name, name, CS_NAME_LEN - 1);
    if (default_action) strncpy(p->default_action, default_action, 15);
    p->architecture = 4;
    return p;
}

void cs_seccomp_add_syscall(cs_seccomp_profile_t *p, const char *syscall_name) {
    if (!p || !syscall_name || p->syscall_count >= CS_MAX_SECCOMP_RULES) return;
    strncpy(p->syscall_names[p->syscall_count], syscall_name, 63);
    p->syscall_count++;
}

void cs_seccomp_block_all(cs_seccomp_profile_t *p) {
    if (!p) return;
    p->syscall_count = 0;
    strncpy(p->default_action, "ERRNO", 15);
}

void cs_seccomp_allow_network(cs_seccomp_profile_t *p) {
    if (!p) return;
    cs_seccomp_add_syscall(p, "socket");
    cs_seccomp_add_syscall(p, "bind");
    cs_seccomp_add_syscall(p, "listen");
    cs_seccomp_add_syscall(p, "accept");
    cs_seccomp_add_syscall(p, "connect");
    cs_seccomp_add_syscall(p, "sendto");
    cs_seccomp_add_syscall(p, "recvfrom");
    cs_seccomp_add_syscall(p, "sendmsg");
    cs_seccomp_add_syscall(p, "recvmsg");
    cs_seccomp_add_syscall(p, "setsockopt");
    cs_seccomp_add_syscall(p, "getsockopt");
}

void cs_seccomp_allow_filesystem(cs_seccomp_profile_t *p) {
    if (!p) return;
    cs_seccomp_add_syscall(p, "open");
    cs_seccomp_add_syscall(p, "openat");
    cs_seccomp_add_syscall(p, "read");
    cs_seccomp_add_syscall(p, "write");
    cs_seccomp_add_syscall(p, "close");
    cs_seccomp_add_syscall(p, "stat");
    cs_seccomp_add_syscall(p, "fstat");
    cs_seccomp_add_syscall(p, "lstat");
    cs_seccomp_add_syscall(p, "mkdir");
    cs_seccomp_add_syscall(p, "unlink");
}

cs_apparmor_profile_t* cs_create_apparmor_profile(const char *name,
                                                    const char *mode) {
    cs_apparmor_profile_t *p = calloc(1, sizeof(cs_apparmor_profile_t));
    if (!p) return NULL;
    if (name) strncpy(p->name, name, CS_NAME_LEN - 1);
    if (mode) strncpy(p->profile_mode, mode, 15);
    else strncpy(p->profile_mode, "enforce", 15);
    return p;
}

void cs_apparmor_add_rule(cs_apparmor_profile_t *p, const char *rule) {
    if (!p || !rule || p->rule_count >= CS_MAX_APPARMOR_RULES) return;
    strncpy(p->rules[p->rule_count], rule, CS_PATH_LEN - 1);
    p->rule_count++;
}

void cs_apparmor_default_docker(cs_apparmor_profile_t *p) {
    if (!p) return;
    cs_apparmor_add_rule(p, "deny /proc/sysrq-trigger w,");
    cs_apparmor_add_rule(p, "deny /sys/kernel/security/** rwklx,");
    cs_apparmor_add_rule(p, "deny /proc/sys/** w,");
    cs_apparmor_add_rule(p, "deny /proc/irq/** w,");
    cs_apparmor_add_rule(p, "deny /proc/bus/** w,");
    cs_apparmor_add_rule(p, "deny capability sys_admin,");
    cs_apparmor_add_rule(p, "deny capability sys_ptrace,");
    cs_apparmor_add_rule(p, "deny capability sys_module,");
}

int cs_check_privileged(const cs_container_t *c) {
    if (!c) return 0;
    return c->privileged;
}

int cs_check_host_network(const cs_container_t *c) {
    if (!c) return 0;
    return c->host_network;
}

int cs_check_host_pid(const cs_container_t *c) {
    if (!c) return 0;
    return c->host_pid;
}

cs_pod_security_level_t cs_validate_pod_security(const cs_container_t *c) {
    if (!c) return CS_POD_PRIVILEGED;
    if (c->privileged || c->host_network || c->host_pid || c->host_ipc) {
        return CS_POD_PRIVILEGED;
    }
    if (c->allow_privilege_escalation || c->cap_count > 0) {
        return CS_POD_BASELINE;
    }
    if (c->read_only_rootfs && c->run_as_non_root && c->uid > 1000) {
        return CS_POD_RESTRICTED;
    }
    return CS_POD_BASELINE;
}

const char* cs_pod_security_violations(const cs_container_t *c,
                                        cs_pod_security_level_t target) {
    if (!c) return "No container";
    cs_pod_security_level_t actual = cs_validate_pod_security(c);
    if (actual > target) {
        static char buf[512];
        snprintf(buf, 511, "Container '%s' is at %s level, but target is %s",
                 c->name, cs_pod_level_name(actual), cs_pod_level_name(target));
        return buf;
    }
    return NULL;
}

cs_network_policy_t* cs_create_network_policy(const char *name,
                                               cs_policy_direction_t dir,
                                               int allow) {
    cs_network_policy_t *np = calloc(1, sizeof(cs_network_policy_t));
    if (!np) return NULL;
    if (name) strncpy(np->name, name, CS_NAME_LEN - 1);
    np->direction = dir;
    np->allow = (unsigned char)(allow ? 1 : 0);
    strncpy(np->protocol, "TCP", 7);
    return np;
}

void cs_network_policy_set_namespace(cs_network_policy_t *np,
                                      const char *from, const char *to) {
    if (!np) return;
    if (from) strncpy(np->from_namespace, from, CS_NAME_LEN - 1);
    if (to) strncpy(np->to_namespace, to, CS_NAME_LEN - 1);
}

void cs_network_policy_set_port(cs_network_policy_t *np,
                                 int from_port, int to_port,
                                 const char *protocol) {
    if (!np) return;
    np->from_port = from_port;
    np->to_port = to_port;
    if (protocol) strncpy(np->protocol, protocol, 7);
}

void cs_network_policy_set_cidr(cs_network_policy_t *np, const char *cidr) {
    if (np && cidr) strncpy(np->cidr, cidr, 44);
}

int cs_validate_network_policy(const cs_network_policy_t *np) {
    if (!np) return 0;
    if (np->from_namespace[0] == '\0' && np->to_namespace[0] == '\0') return 0;
    return 1;
}

int cs_evaluate_network_policy(const cs_network_policy_t *np,
                                const char *from_ns,
                                const char *to_ns,
                                int port,
                                const char *direction) {
    if (!np || !from_ns || !to_ns) return 0;
    if (np->from_namespace[0] && strcmp(np->from_namespace, from_ns) != 0) return 0;
    if (np->to_namespace[0] && strcmp(np->to_namespace, to_ns) != 0) return 0;
    if (np->from_port && np->from_port != port) return 0;
    if (direction) {
        cs_policy_direction_t dir = (strcmp(direction, "ingress") == 0) ?
                                     CS_INGRESS : CS_EGRESS;
        if (np->direction != dir) return 0;
    }
    return np->allow ? 2 : -1;
}

void cs_add_secret_to_container(cs_container_t *c, const char *secret_name) {
    if (!c || !secret_name || c->secret_count >= CS_MAX_SECRETS) return;
    strncpy(c->secret_names[c->secret_count], secret_name, CS_NAME_LEN - 1);
    c->secret_count++;
}

int cs_check_external_secrets(const cs_container_t *c) {
    if (!c) return 0;
    for (int i = 0; i < c->secret_count; i++) {
        if (strstr(c->secret_names[i], "vault:") ||
            strstr(c->secret_names[i], "arn:aws:secretsmanager:")) {
            return 1;
        }
    }
    return 0;
}

int cs_sign_image(cs_image_t *img, cs_signature_type_t type,
                   const char *signer_name) {
    if (!img || !signer_name) return -1;
    UNUSED(type);
    return 0;
}

int cs_verify_image_signature(const cs_image_t *img,
                               const char *signer_name) {
    if (!img || !signer_name) return -1;
    return 1;
}

int cs_verify_cosign(const cs_image_t *img, const char *public_key) {
    if (!img || !public_key) return -1;
    return (public_key[0] != '\0') ? 0 : -1;
}

void cs_init_state(cs_state_t *state) {
    if (!state) return;
    memset(state, 0, sizeof(cs_state_t));
}

const char* cs_severity_name(cs_severity_t s) {
    switch (s) {
        case CS_SEVERITY_CRITICAL: return "CRITICAL";
        case CS_SEVERITY_HIGH:     return "HIGH";
        case CS_SEVERITY_MEDIUM:   return "MEDIUM";
        case CS_SEVERITY_LOW:      return "LOW";
        case CS_SEVERITY_INFO:     return "INFO";
        default: return "UNKNOWN";
    }
}

const char* cs_pod_level_name(cs_pod_security_level_t level) {
    switch (level) {
        case CS_POD_PRIVILEGED: return "privileged";
        case CS_POD_BASELINE:   return "baseline";
        case CS_POD_RESTRICTED: return "restricted";
        default: return "unknown";
    }
}

void cs_print_scan_report(const cs_image_t *img) {
    if (!img) return;
    printf("Image Scan Report: %s:%s\n", img->image_name, img->image_tag);
    printf("  Digest:          %s\n", img->image_digest);
    printf("  Scan Time:       %s", ctime(&img->last_scan));
    printf("  Size:            %d MB (%d layers)\n", img->size_bytes / 1048576, img->layer_count);
    printf("  Scan Pass:       %s\n", img->scan_pass ? "PASS" : "FAIL");
    printf("  Malware:         %s\n", img->malware_detected ? "DETECTED!" : "none");
    if (img->malware_detected) printf("    -> %s\n", img->malware_detail);
    printf("  Rootfs Read-only:%s\n", img->read_only_rootfs ? "yes" : "no");
    printf("  Run as Non-Root: %s\n", img->run_as_non_root ? "yes" : "no");
    printf("  Vulns: Critical=%d High=%d Medium=%d Low=%d\n",
           cs_count_severity(img, CS_SEVERITY_CRITICAL),
           cs_count_severity(img, CS_SEVERITY_HIGH),
           cs_count_severity(img, CS_SEVERITY_MEDIUM),
           cs_count_severity(img, CS_SEVERITY_LOW));
    for (int i = 0; i < img->vuln_count; i++) {
        printf("    %s  %s  %.1f  %s  fix=%s\n",
               img->vulnerabilities[i].cve_id,
               cs_severity_name(img->vulnerabilities[i].severity),
               img->vulnerabilities[i].cvss_score,
               img->vulnerabilities[i].package_name,
               img->vulnerabilities[i].fix_available ? "yes" : "no");
    }
}

void cs_print_container_report(const cs_container_t *c) {
    if (!c) return;
    cs_pod_security_level_t level = cs_validate_pod_security(c);
    printf("Container Report: %s (%s)\n", c->name, c->namespace);
    printf("  Image:           %s\n", c->image_name);
    printf("  Pod Security:    %s\n", cs_pod_level_name(level));
    printf("  Privileged:      %s\n", c->privileged ? "YES (DANGER)" : "no");
    printf("  Host Network:    %s\n", c->host_network ? "YES" : "no");
    printf("  Host PID:        %s\n", c->host_pid ? "YES" : "no");
    printf("  Run as Non-Root: %s\n", c->run_as_non_root ? "yes" : "NO");
    printf("  Read-Only Root:  %s\n", c->read_only_rootfs ? "yes" : "no");
    printf("  Seccomp Profile: %s\n", c->seccomp_profile[0] ? c->seccomp_profile : "none");
    printf("  AppArmor:        %s\n", c->apparmor_profile[0] ? c->apparmor_profile : "none");
    printf("  SELinux:         %s\n", c->selinux_label[0] ? c->selinux_label : "none");
    printf("  Secrets:         %d\n", c->secret_count);
    printf("  Signatures:      %d (type=%d)\n", c->signer_count, c->sig_type);
}

void cs_print_summary(const cs_state_t *state) {
    if (!state) return;
    printf("Container Security Summary:\n");
    printf("  Images Scanned:  %d\n", state->scanned_images);
    printf("  Failed Scans:    %d\n", state->failed_scans);
    printf("  Images in Registry: %d\n", state->image_count);
    printf("  Privileged Ctrs: %d\n", state->privileged_containers);
    printf("  Blocked Deployments: %d\n", state->blocked_deployments);
    printf("  Network Policies: %d\n", state->network_policy_count);
    printf("  Seccomp Profiles: %d\n", state->seccomp_count);
    printf("  AppArmor Profiles: %d\n", state->apparmor_count);
}
