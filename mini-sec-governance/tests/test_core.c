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
    int id = iso27001_add_asset(&isms, "customer-db", "dba-team", "RESTRICTED", 100000.0, 1);
    CHECK(id >= 1, "add asset failed (id < 1)");
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
    int count = iso27001_generate_soa(&isms);
    CHECK(count > 0, "generate soa failed");
    CHECK(isms.soa_count == isms.control_count, "soa count != control count");
    PASS();
    return 0;
}

/* ── SOC2 Tests ── */
static int test_soc2_add_control(void) {
    TEST("soc2_add_control");
    SOC2_Engagement eng;
    CHECK(soc2_init_engagement(&eng) == 0, "init engagement failed");
    int id = soc2_add_control(&eng, SOC2_TC_SECURITY, "Access Control",
                           "Review user access quarterly", "Check access logs");
    CHECK(id >= 1, "add control failed");
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
    int id = risk_add_entry(&reg, 1, 1, RISK_PROB_LOW, RISK_IMPACT_MAJOR, 100000.0);
    CHECK(id >= 1, "add entry failed");
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
    risk_add_entry(&reg, 1, 1, RISK_PROB_HIGH, RISK_IMPACT_MAJOR, 5000.0);
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
    int id = comp_add_policy(&eng, "data-encryption", "Ensure data is encrypted at rest",
                          "resource.encryption == true", "config.db.encryption",
                          "true", 3, regs, 1);
    CHECK(id >= 1, "add policy failed");
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
    int chk = comp_check_policy(&eng, 1, "true");
    CHECK(chk >= 1, "check policy failed");
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
    comp_check_policy(&eng, 1, "expected");
    comp_check_policy(&eng, 2, "mismatch");
    double score = comp_compliance_score(&eng);
    CHECK(score >= 0.0 && score <= 100.0, "score out of range");
    PASS();
    return 0;
}

/* ── New: FAIR Model Tests ── */
static int test_fair_model(void) {
    TEST("fair_model");
    Risk_FAIR_Model fair;
    CHECK(risk_fair_init(&fair, 10.0, 0.6, 0.3, 5000.0, 10000.0, 20000.0) == 0, "fair init failed");
    risk_fair_compute(&fair);
    CHECK(fair.vulnerability > 0.0, "vuln should be > 0");
    CHECK(fair.loss_event_frequency > 0.0, "LEF should be > 0");
    CHECK(fair.annualized_loss > 0.0, "ALE should be > 0");
    CHECK(fair.risk_exposure > 0.0, "exposure should be > 0");
    PASS();
    return 0;
}

/* ── New: Monte Carlo Test ── */
static int test_monte_carlo(void) {
    TEST("monte_carlo");
    Risk_Register reg;
    risk_init(&reg, 100.0);
    risk_add_asset(&reg, "test", RISK_CLASS_INTERNAL, "owner", 10000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "t", "d", "a", RISK_PROB_MODERATE, 0.5, 1.0);
    risk_add_entry(&reg, 1, 1, RISK_PROB_MODERATE, RISK_IMPACT_MODERATE, 10000.0);
    Risk_MonteCarloResult mc;
    CHECK(risk_monte_carlo_ale(&reg, 1, 1000, &mc) == 0, "MC sim failed");
    CHECK(mc.iterations == 1000, "iterations wrong");
    CHECK(mc.mean > 0.0, "mean should be > 0");
    CHECK(mc.p95 >= mc.p50, "p95 should be >= p50");
    PASS();
    return 0;
}

/* ── New: Bow-Tie Test ── */
static int test_bowtie(void) {
    TEST("bowtie_analysis");
    Risk_BowtieModel bowtie;
    risk_bowtie_init(&bowtie, "Data Breach", "Phishing Attack");
    risk_bowtie_add_preventive(&bowtie, "MFA", "Hardware tokens", 0.95, 1);
    risk_bowtie_add_preventive(&bowtie, "Training", "Phishing sim", 0.70, 1);
    risk_bowtie_add_corrective(&bowtie, "EDR", "Auto isolate", 0.90, 1);
    double score = risk_bowtie_risk_score(&bowtie);
    CHECK(score > 0.0, "bowtie score should be > 0");
    CHECK(score < 1.0, "bowtie score should be < 1 with good barriers");
    PASS();
    return 0;
}

/* ── New: Portfolio Optimization Test ── */
static int test_portfolio(void) {
    TEST("portfolio_optimization");
    Risk_Register reg;
    risk_init(&reg, 100.0);
    risk_add_asset(&reg, "a1", RISK_CLASS_INTERNAL, "o", 1000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "t1", "d", "a", RISK_PROB_HIGH, 0.8, 2.0);
    risk_add_entry(&reg, 1, 1, RISK_PROB_HIGH, RISK_IMPACT_MAJOR, 50000.0);
    risk_set_treatment(&reg, 1, RISK_TREATMENT_MITIGATE, "Firewall", 10000.0);
    Risk_PortfolioItem items[64];
    int count = risk_portfolio_build(&reg, items, 64, 50000.0);
    CHECK(count >= 1, "should have at least 1 portfolio item");
    int sel = risk_portfolio_optimize(items, count, 50000.0);
    CHECK(sel >= 0, "optimization should not fail");
    PASS();
    return 0;
}

/* ── New: ISO27001 KPI / Incident / Clause Tests ── */
static int test_iso27001_kpi(void) {
    TEST("iso27001_kpi");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2025);
    int kid = iso27001_add_kpi(&isms, "Test KPI", "metric", 95.0, 80.0, 60.0, 5);
    CHECK(kid >= 1, "add kpi failed");
    CHECK(iso27001_update_kpi(&isms, 1, 92.0) == 0, "update kpi failed");
    CHECK(isms.kpis[0].current_value == 92.0, "kpi value wrong");
    PASS();
    return 0;
}

static int test_iso27001_incident(void) {
    TEST("iso27001_incident");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2025);
    int iid = iso27001_add_incident(&isms, "Test", "desc", "tester", 2025, 6, 3);
    CHECK(iid >= 1, "add incident failed");
    CHECK(iso27001_resolve_incident(&isms, 1, "bug", "fix", 2.0, 5.0) == 0, "resolve failed");
    double mttr;
    CHECK(iso27001_mean_time_to_resolve(&isms, &mttr) == 0, "mttr failed");
    CHECK(mttr > 0.0, "mttr should be > 0");
    PASS();
    return 0;
}

static int test_iso27001_clauses(void) {
    TEST("iso27001_clauses");
    ISO27001_ISMS isms;
    iso27001_init(&isms, 2025);
    iso27001_init_clauses(&isms);
    CHECK(isms.clause_count >= 5, "clause count too low");
    CHECK(iso27001_update_clause(&isms, 4, 5) == 0, "update clause failed");
    int pct = iso27001_clause_compliance_pct(&isms, 4);
    CHECK(pct > 0, "compliance pct should be > 0");
    PASS();
    return 0;
}

/* ── New: NIST CSF Maturity / SCRM Tests ── */
static int test_nist_maturity(void) {
    TEST("nist_maturity");
    NIST_CSF_Framework fw;
    nist_csf_init(&fw);
    nist_csf_set_org_tier(&fw, NIST_TIER_3_REPEATABLE);
    nist_csf_add_profile_item(&fw, "ID.AM-1", NIST_TIER_3_REPEATABLE, NIST_TIER_4_ADAPTIVE, "fix", 1);
    NIST_CSF_MaturityAssessment ma;
    CHECK(nist_csf_assess_maturity(&fw, &ma) == 0, "maturity assess failed");
    CHECK(ma.composite_score > 0.0, "maturity score should be > 0");
    CHECK(ma.assessed_tier >= NIST_TIER_1_PARTIAL, "tier should be valid");
    PASS();
    return 0;
}

static int test_nist_scrm(void) {
    TEST("nist_scrm");
    NIST_CSF_Framework fw;
    nist_csf_init(&fw);
    int sid = nist_scrm_add_supplier(&fw, "TestVendor", NIST_SCRM_TIER1_DIRECT, 1, 50.0, 2025, 1, 1);
    CHECK(sid >= 1, "add supplier failed");
    int crit_ids[16];
    int crit_count = nist_scrm_critical_suppliers(&fw, crit_ids, 16);
    CHECK(crit_count == 1, "critical supplier count wrong");
    double risk = nist_scrm_aggregate_risk(&fw);
    CHECK(risk > 0.0, "aggregate risk should be > 0");
    PASS();
    return 0;
}

/* ── New: Compliance Advanced Tests ── */
static int test_compliance_remediation(void) {
    TEST("comp_remediation");
    Compliance_Engine eng;
    comp_init(&eng);
    int rid = comp_add_remediation(&eng, 0, 1, "Fix it", "team", 1, 7, 500.0);
    CHECK(rid >= 1, "add remediation failed");
    CHECK(comp_remediate_close(&eng, 1) == 0, "close remediation failed");
    PASS();
    return 0;
}

static int test_compliance_chain_verify(void) {
    TEST("comp_chain_verify");
    Compliance_Engine eng;
    comp_init(&eng);
    comp_add_log(&eng, "admin", "action1", "res1", "ok");
    comp_add_log(&eng, "admin", "action2", "res2", "ok");
    comp_add_log(&eng, "admin", "action3", "res3", "ok");
    int valid = comp_verify_chain(&eng);
    CHECK(valid == 1, "chain should be valid");
    PASS();
    return 0;
}

static int test_compliance_trend(void) {
    TEST("comp_trend");
    Compliance_Engine eng;
    comp_init(&eng);
    Compliance_Regulation regs[] = {COMP_REG_GDPR};
    comp_add_policy(&eng, "p1", "d", "r", "path", "val", 1, regs, 1);
    comp_check_policy(&eng, 1, "val");
    comp_record_trend(&eng);
    comp_record_trend(&eng);
    CHECK(eng.trend_count == 2, "trend count wrong");
    double pred;
    comp_forecast_compliance(&eng, 30, &pred);
    CHECK(pred >= 0.0 && pred <= 100.0, "forecast out of range");
    PASS();
    return 0;
}

static int test_compliance_maturity(void) {
    TEST("comp_maturity");
    Compliance_Engine eng;
    comp_init(&eng);
    comp_add_regulation(&eng, COMP_REG_GDPR);
    Compliance_Regulation regs[] = {COMP_REG_GDPR};
    comp_add_policy(&eng, "p1", "d", "r", "p", "v", 1, regs, 1);
    comp_add_policy(&eng, "p2", "d", "r", "p", "v", 1, regs, 1);
    comp_add_control(&eng, "c1", COMP_REG_GDPR, "desc");
    comp_add_control(&eng, "c2", COMP_REG_GDPR, "desc");
    comp_add_log(&eng, "a", "a", "r", "ok");
    comp_add_log(&eng, "a", "a", "r", "ok");
    comp_assess_maturity(&eng);
    CHECK(eng.maturity.overall >= COMP_MATURITY_INITIAL, "maturity should be valid");
    CHECK(eng.maturity.score >= 0.0 && eng.maturity.score <= 100.0, "score out of range");
    PASS();
    return 0;
}

/* ── New: SOC2 Statistical Sampling & Bridge Letter ── */
static int test_soc2_sampling(void) {
    TEST("soc2_sampling");
    SOC2_AuditSample s;
    int n = soc2_calculate_sample_size(1000, 0.95, 0.05, 0.02, &s);
    CHECK(n > 0, "sample size should be > 0");
    CHECK(s.sample_size > 0, "sample size field should be > 0");
    int ok = soc2_evaluate_sample(&s, 5);
    CHECK(ok >= 0, "sample evaluation should return 0 or 1");
    PASS();
    return 0;
}

static int test_soc2_bridge_letter(void) {
    TEST("soc2_bridge_letter");
    SOC2_Engagement eng;
    soc2_init_engagement(&eng);
    SOC2_AuditReport report;
    soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_II, 2025,
        SOC2_TC_SECURITY, "Auditor", "Org");
    SOC2_BridgeLetter letter;
    CHECK(soc2_generate_bridge_letter(&report, &eng, 1, 6, 0, NULL, &letter) == 0, "bridge letter failed");
    CHECK(letter.report_year == 2025, "year wrong");
    CHECK(letter.has_material_changes == 0, "should have no changes");
    PASS();
    return 0;
}

static int test_soc2_tsc_coverage(void) {
    TEST("soc2_tsc_coverage");
    SOC2_Engagement eng;
    soc2_init_engagement(&eng);
    soc2_add_control(&eng, SOC2_TC_SECURITY, "AC-1", "Access", "Test");
    SOC2_AuditReport report;
    soc2_generate_report(&eng, &report, SOC2_REPORT_TYPE_I, 2025,
        SOC2_TC_SECURITY, "A", "O");
    double cov;
    CHECK(soc2_tsc_coverage(&report, SOC2_TC_SECURITY, &cov) == 0, "tsc coverage failed");
    CHECK(cov >= 0.0 && cov <= 100.0, "coverage out of range");
    PASS();
    return 0;
}

/* ── New: Risk Aggregate Metrics Test ── */
static int test_risk_metrics(void) {
    TEST("risk_metrics");
    Risk_Register reg;
    risk_init(&reg, 999.0);
    risk_add_asset(&reg, "a", RISK_CLASS_INTERNAL, "o", 1000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "t", "d", "a", RISK_PROB_HIGH, 0.8, 2.0);
    risk_add_entry(&reg, 1, 1, RISK_PROB_HIGH, RISK_IMPACT_MAJOR, 50000.0);
    double exposure = risk_total_exposure(&reg);
    CHECK(exposure > 0.0, "exposure should be > 0");
    double var95 = risk_value_at_risk(&reg, 0.95);
    CHECK(var95 > 0.0, "VaR should be > 0");
    double es95 = risk_expected_shortfall(&reg, 0.95);
    CHECK(es95 >= var95, "ES should be >= VaR");
    PASS();
    return 0;
}

/* ── New: Bayesian Inference Test ── */
static int test_risk_bayesian(void) {
    TEST("risk_bayesian");
    Risk_Register reg;
    risk_init(&reg, 10.0);
    risk_add_asset(&reg, "a", RISK_CLASS_INTERNAL, "o", 1000.0, 1);
    risk_add_threat(&reg, RISK_STRIDE_SPOOFING, "t", "d", "a", RISK_PROB_MODERATE, 0.5, 1.0);
    risk_add_entry(&reg, 1, 1, RISK_PROB_MODERATE, RISK_IMPACT_MODERATE, 10000.0);
    double post;
    risk_bayesian_network_inference(&reg, 1, &post, 0.9);
    CHECK(post > 0.0 && post <= 1.0, "posterior out of range");
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
    /* ── New API tests ── */
    failed += test_fair_model();
    failed += test_monte_carlo();
    failed += test_bowtie();
    failed += test_portfolio();
    failed += test_iso27001_kpi();
    failed += test_iso27001_incident();
    failed += test_iso27001_clauses();
    failed += test_nist_maturity();
    failed += test_nist_scrm();
    failed += test_compliance_remediation();
    failed += test_compliance_chain_verify();
    failed += test_compliance_trend();
    failed += test_compliance_maturity();
    failed += test_soc2_sampling();
    failed += test_soc2_bridge_letter();
    failed += test_soc2_tsc_coverage();
    failed += test_risk_metrics();
    failed += test_risk_bayesian();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
