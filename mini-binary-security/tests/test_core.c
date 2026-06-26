/*
 * mini-binary-security — Core Tests
 *
 * Unit tests for buffer overflow, ROP gadgets, mitigations, format strings, fuzzing.
 */
#include "../include/buffer_overflow.h"
#include "../include/rop_gadget.h"
#include "../include/mitigation_def.h"
#include "../include/format_string.h"
#include "../include/fuzzing_tool.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0, tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(cond, msg) if (!(cond)) FAIL(msg)

/* ── Buffer Overflow Tests ── */
static int test_int_overflow_check(void) {
    TEST("int_overflow_check");
    CHECK(int_ovf_check_add_int32(0x7FFFFFFF, 1), "MAX_INT+1 should overflow");
    CHECK(!int_ovf_check_add_int32(10, 20), "10+20 should not overflow");
    CHECK(int_ovf_check_mul_size((size_t)0x100000000ULL, (size_t)0x100000000ULL), "large mul should overflow");
    CHECK(!int_ovf_check_mul_size(100, 200), "100*200 should not overflow");
    PASS();
    return 0;
}

static int test_uaf_tracker(void) {
    TEST("uaf_tracker");
    uaf_tracker_t tracker;
    uaf_tracker_init(&tracker);
    int dummy;
    uaf_tracker_add(&tracker, &dummy, sizeof(dummy));
    CHECK(tracker.count == 1, "add failed");
    uaf_tracker_mark_free(&tracker, &dummy);
    CHECK(uaf_tracker_is_dangling(&tracker, &dummy), "should be dangling after free");
    PASS();
    return 0;
}

static int test_double_free_tracker(void) {
    TEST("double_free_tracker");
    df_tracker_t tracker;
    df_tracker_init(&tracker);
    int dummy;
    CHECK(!df_tracker_check(&tracker, &dummy), "first free should be ok");
    df_tracker_check(&tracker, &dummy); /* record it */
    CHECK(df_tracker_check(&tracker, &dummy), "second free should be detected");
    PASS();
    return 0;
}

/* ── ROP Gadget Tests ── */
static int test_rop_gadget_db(void) {
    TEST("rop_gadget_db");
    gadget_db_t db;
    rop_gadget_db_init(&db);
    uint8_t bytes[] = {0x5f, 0xc3}; /* pop rdi; ret */
    CHECK(rop_gadget_db_add(&db, 0x401000, bytes, 2), "add gadget failed");
    CHECK(db.count == 1, "gadget count wrong");
    rop_gadget_classify(&db.gadgets[0]);
    CHECK(db.gadgets[0].class == GADGET_POP_REG, "classify wrong");
    PASS();
    return 0;
}

static int test_rop_chain_append(void) {
    TEST("rop_chain_append");
    rop_chain_t chain;
    rop_chain_init(&chain);
    gadget_db_t db;
    rop_gadget_db_init(&db);
    uint8_t bytes[] = {0x5f, 0xc3};
    rop_gadget_db_add(&db, 0x401000, bytes, 2);
    rop_gadget_classify(&db.gadgets[0]);
    CHECK(rop_chain_append(&chain, &db.gadgets[0], 0xDEADBEEF, "pop rdi gadget"), "append failed");
    CHECK(chain.count == 1, "chain count wrong");
    PASS();
    return 0;
}

/* ── Mitigation Tests ── */
static int test_mitigation_profile(void) {
    TEST("mitigation_profile");
    security_profile_t profile;
    mitigation_profile_init(&profile);
    mitigation_check_aslr(&profile);
    mitigation_check_nx(&profile);
    mitigation_check_canary(&profile);
    mitigation_check_relro(&profile);
    mitigation_check_pie(&profile);
    security_level_t level = mitigation_assess_level(&profile);
    CHECK(level >= SEC_LVL_LOW && level <= SEC_LVL_MAX, "invalid security level");
    uint32_t score = mitigation_score(&profile);
    CHECK(score <= 100, "score > 100");
    PASS();
    return 0;
}

static int test_mitigation_is_protected(void) {
    TEST("mitigation_is_protected");
    security_profile_t profile;
    mitigation_profile_init(&profile);
    profile.flags = MITIG_ASLR | MITIG_NX | MITIG_CANARY | MITIG_PIE;
    CHECK(mitigation_is_protected(&profile, MITIG_ASLR), "ASLR should be protected");
    CHECK(mitigation_is_protected(&profile, MITIG_NX), "NX should be protected");
    CHECK(!mitigation_is_protected(&profile, MITIG_CFI), "CFI should not be protected");
    PASS();
    return 0;
}

/* ── Format String Tests ── */
static int test_fmt_parse(void) {
    TEST("fmt_parse");
    fmt_parse_result_t result;
    fmt_parse_result_init(&result);
    fmt_parse("%d %s %n", &result);
    CHECK(result.count == 3, "parse count wrong");
    CHECK(result.has_n_write, "should detect %n");
    CHECK(!result.has_leak, "no leak format");
    PASS();
    return 0;
}

static int test_fmt_payload_has_null(void) {
    TEST("fmt_payload_has_null");
    char payload[] = "AAAA\x00BBBB";
    CHECK(fmt_payload_has_null(payload), "null byte not detected");
    CHECK(!fmt_payload_has_null("no null bytes here"), "false null positive");
    PASS();
    return 0;
}

/* ── Fuzzing Tests ── */
static int test_fuzzer_init_add_seed(void) {
    TEST("fuzzer_init_add_seed");
    fuzzer_state_t fs;
    fuzzer_init(&fs, "/tmp/seeds", "/tmp/crashes");
    const char *seed = "FUZZ";
    CHECK(fuzzer_add_seed(&fs, (const uint8_t *)seed, 4, "seed1"), "add seed failed");
    CHECK(fs.corpus.count == 1, "corpus count wrong");
    CHECK(fs.corpus.entries[0].len == 4, "seed len wrong");
    CHECK(memcmp(fs.corpus.entries[0].data, "FUZZ", 4) == 0, "seed data wrong");
    fuzzer_free(&fs);
    PASS();
    return 0;
}

static int test_coverage_update(void) {
    TEST("coverage_update");
    coverage_map_t cm;
    fuzz_coverage_init(&cm);
    uint8_t data1[] = {0x01, 0x02, 0x03};
    uint8_t data2[] = {0x01, 0x02, 0x03, 0x04};
    CHECK(fuzz_coverage_update(&cm, data1, 3), "first update should find new coverage");
    fuzz_coverage_reset_check(&cm);
    CHECK(fuzz_coverage_update(&cm, data2, 4), "second update should find new coverage");
    PASS();
    return 0;
}

int main(void) {
    printf("=== mini-binary-security Unit Tests ===\n\n");

    int failed = 0;
    failed += test_int_overflow_check();
    failed += test_uaf_tracker();
    failed += test_double_free_tracker();
    failed += test_rop_gadget_db();
    failed += test_rop_chain_append();
    failed += test_mitigation_profile();
    failed += test_mitigation_is_protected();
    failed += test_fmt_parse();
    failed += test_fmt_payload_has_null();
    failed += test_fuzzer_init_add_seed();
    failed += test_coverage_update();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, failed);
    return failed > 0 ? 1 : 0;
}
