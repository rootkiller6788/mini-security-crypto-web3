/*
 * mini-sec-governance — Core Tests
 *
 * Unit tests for ISO27001, SOC2, NIST CSF, risk assessment, compliance automation.
 */
#include "../include/iso27001_mgr.h"
#include "../include/soc2_audit.h"
#include "../include/nist_csf.h"
#include "../include/risk_assess.h"
#include "../include/compliance_auto.h"
#include <stdio.h>
#include <string.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── ISO27001 Tests ── */
static int test_iso27001_init(void) {
    TEST("iso27001_init");
    ISO27001_ISMS isms;
    CHECK(iso27001_init(&isms, 2024) == 0, "init failed");
    CHECK(isms.cert_year == 2024, "cert year wrong");
    CHECK(isms.active, "isms not active");
    PASS();
    return 0;
}

static int test_iso27001_add_asset(void) {
    TEST("iso27001_add_asset");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2024);
    CHECK(iso27001_add_asset(&isms, "customer-db", "dba-team", "RESTRICTED", 100000.0, 1) == 0, "add asset failed");
    CHECK(isms.asset_count == 1, "asset count wrong");
    CHECK(strcmp(isms.assets[0].name, "customer-db") == 0, "asset name wrong");
    PASS();
    return 0;
}

static int test_iso27001_generate_soa(void) {
    TEST("iso27001_generate_soa");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2024);
    iso27001_load_annex_a(&isms);
    CHECK(iso27001_generate_soa(&isms) == 0, "generate soa failed");
    CHECK(isms.soa_count == isms.control_count, "soa count != control count");
    PASS();
    return 0;
}

/* ── SOC2 Tests ── */
static int test_soc2_add_control(void) {
    TEST("soc2_add_control");
    SOC2_Engagement eng;
    CHECK(soc2_init_engagement(&eng) == 0, "init engagement failed");
    CHECK(soc2_add_control(&eng, SOC2_TC_SECURITY, "Access Control",
                           "Review user access quarterly", "Check access logs") == 0, "add control failed");
    CHECK(eng.activity_count == 1, "activity count wrong");
    CHECK(eng.activities[0].category == SOC2_TC_SECURITY, "category wrong");
    PASS();
    return 0;
}

static int test_soc2_trust_criteria_name(void) {
    TEST("soc2_trust_criteria_name");
    const char *name = soc2_trust_criteria_name(SOC2_TC_AVAILABILITY);
    CHECK(name != NULL, "name is NULL");
    CHECK(strlen(name) > 0, "name is empty");
    PASS();
    return 0;
}

/* ── NIST CSF Tests ── */
static int test_nist_csf_init_tier(void) {
    TEST("nist_csf_init_tier");
    NIST_CSF_Framework fw;
    CHECK(nist_csf_init(&fw) == 0, "init failed");
    CHECK(nist_csf_set_org_tier(&fw, NIST_TIER_3_REPEATABLE) == 0, "set tier failed");
    CHECK(fw.org_tier == NIST_TIER_3_REPEATABLE, "tier wrong");
    PASS();
    return 0;
}

static int test_nist_csf_function_name(void) {
    TEST("nist_csf_function_name");
    CHECK(strcmp(nist_csf_function_name(NIST_CSF_IDENTIFY), "Identify") == 0, "IDENTIFY name wrong");
    CHECK(strcmp(nist_csf_function_name(NIST_CSF_PROTECT), "Protect") == 0, "PROTECT name wrong");
    CHECK(strcmp(nist_csf_function_name(NIST_CSF_DETECT), "Detect") == 0, "DETECT name wrong");
    PASS();
    return 0;
}

/* ── Risk Assessment Tests ── */
static int test_risk_add_entry(void) {
    TEST("risk_add_entry");
    Risk_Register reg;
    CHECK(risk_init(&reg, 12.0) == 0, "risk init failed");
    risk_add_asset(&reg, "payment-gateway", RISK_CLASS_RESTRICTED, "fin-team", 500000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_TAMPERING, "Data Tampering",
                    "Modification of payment data", "external", RISK_PROB_MODERATE, 0.7, 2.0);
    CHECK(risk_add_entry(&reg, 0, 0, RISK_PROB_LOW, RISK_IMPACT_MAJOR, 100000.0) == 0, "add entry failed");
    CHECK(reg.risk_count == 1, "risk count wrong");
    PASS();
    return 0;
}

static int test_risk_heatmap(void) {
    TEST("risk_heatmap");
    Risk_Register reg;
    risk_init(&reg, 12.0);
    risk_add_asset(&reg, "asset1", RISK_CLASS_INTERNAL, "owner", 1000.0, 0);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "Spoofing", "desc", "actor", RISK_PROB_HIGH, 0.5, 1.0);
    risk_add_entry(&reg, 0, 0, RISK_PROB_HIGH, RISK_IMPACT_MAJOR, 5000.0);
    int matrix[5][5];
    CHECK(risk_heatmap(&reg, matrix) == 0, "heatmap failed");
    CHECK(matrix[RISK_PROB_HIGH - 1][RISK_IMPACT_MAJOR - 1] > 0, "expected risk in cell");
    PASS();
    return 0;
}

/* ── Compliance Automation Tests ── */
static int test_compliance_add_policy(void) {
    TEST("compliance_add_policy");
    Compliance_Engine eng;
    CHECK(comp_init(&eng) == 0, "comp init failed");
    Compliance_Regulation regs[] = {COMP_REG_GDPR};
    CHECK(comp_add_policy(&eng, "data-encryption", "Ensure data is encrypted at rest",
                          "resource.encryption == true", "config.db.encryption",
                          "true", 3, regs, 1) == 0, "add policy failed");
    CHECK(eng.policy_count == 1, "policy count wrong");
    PASS();
    return 0;
}

static int test_compliance_check_policy(void) {
    TEST("compliance_check_policy");
    Compliance_Engine eng;
    comp_init(&eng);
    Compliance_Regulation regs[] = {COMP_REG_PCI_DSS};
    comp_add_policy(&eng, "encryption-policy", "Encryption required",
                    "resource.encryption == true", "config.db.encryption", "true", 2, regs, 1);
    CHECK(comp_check_policy(&eng, 0, "true") == 0, "check policy failed");
    CHECK(eng.check_count == 1, "check count wrong");
    CHECK(eng.checks[0].status == COMP_STATUS_PASS, "should pass");
    PASS();
    return 0;
}

static int test_compliance_score(void) {
    TEST("compliance_score");
    Compliance_Engine eng;
    comp_init(&eng);
    Compliance_Regulation regs[] = {COMP_REG_ISO27001};
    comp_add_policy(&eng, "policy1", "desc", "rule", "path", "expected", 1, regs, 1);
    comp_add_policy(&eng, "policy2", "desc", "rule", "path", "expected", 1, regs, 1);
    comp_check_policy(&eng, 0, "expected");
    comp_check_policy(&eng, 1, "mismatch");
    double score = comp_compliance_score(&eng);
    CHECK(score >= 0.0 && score <= 100.0, "score out of range");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-sec-governance Unit Tests ===\n\n");

    int failed = 0;
    failed += test_iso27001_init();
    failed += test_iso27001_add_asset();
    failed += test_iso27001_generate_soa();
    failed += test_soc2_add_control();
    failed += test_soc2_trust_criteria_name();
    failed += test_nist_csf_init_tier();
    failed += test_nist_csf_function_name();
    failed += test_risk_add_entry();
    failed += test_risk_heatmap();
    failed += test_compliance_add_policy();
    failed += test_compliance_check_policy();
    failed += test_compliance_score();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
