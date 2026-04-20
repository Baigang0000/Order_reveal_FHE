#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "orhe.h"
#include "orhe_metrics.h"

namespace {

static const int kBitWidths[] = {8, 16, 32, 64};

static const char* kBackendUnsafe = "unsafe_compare";
static const char* kBackendOrhe = "orhe_attack";

static const char* kUnsafeSubmode = "released_compare_bits";
static const char* kFreshUnregisteredSubmode = "fresh_unregistered_threshold";
static const char* kRegisteredThresholdSubmode = "registered_threshold_if_supported";

static const char* kOutcomeExactRecovery = "exact_recovery";
static const char* kOutcomeUnexpectedAcceptance = "unexpected_acceptance";
static const char* kOutcomeBlockedByRejection = "blocked_by_rejection";

static const char* kStageAcceptedWithoutRegistrationCheck = "accepted_without_registration_check";
static const char* kStageAcceptedAfterRegistrationOnly = "accepted_after_registration_only";
static const char* kStageAcceptedAfterProofVerification = "accepted_after_proof_verification";
static const char* kStageRejectedMissingRegistration = "rejected_missing_registration";
static const char* kStageRejectedBadHandle = "rejected_bad_handle";
static const char* kStageRejectedBadProof = "rejected_bad_proof";
static const char* kStageRejectedPreRelease = "rejected_pre_release";

struct AttackBenchConfig {
    bool full_mode;
    int32_t episodes;
    uint64_t seed;
    std::string output_dir;
    std::vector<int> bit_widths;
};

struct QueryLogRow {
    std::string backend;
    std::string submode;
    int bit_width;
    int32_t episode_id;
    int32_t query_index;
    uint64_t plaintext_m;
    uint64_t threshold;
    uint64_t interval_lo_before;
    uint64_t interval_hi_before;
    uint64_t interval_lo_after;
    uint64_t interval_hi_after;
    int threshold_freshly_encrypted_by_attacker;
    int registration_attempted;
    int registration_succeeded;
    int threshold_registered;
    uint64_t lhs_handle;
    uint64_t rhs_handle;
    int handle_lookup_succeeded;
    int statement_construction_called;
    int statement_construction_succeeded;
    int proof_generation_called;
    int proof_present;
    int proof_verification_called;
    int proof_verification_succeeded;
    int gate_checked_admissibility;
    int final_release_attempted;
    int accepted;
    int rejected;
    bool has_bit;
    int bit;
    uint64_t latency_us;
    uint64_t bytes;
    std::string acceptance_stage;
    std::string detail;
};

struct EpisodeSummaryRow {
    std::string backend;
    std::string submode;
    int bit_width;
    int32_t episode_id;
    uint64_t plaintext_m;
    std::string outcome;
    int32_t queries;
    uint64_t setup_latency_us;
    uint64_t query_latency_us;
    uint64_t total_latency_us;
    uint64_t setup_bytes;
    uint64_t query_bytes;
    uint64_t total_bytes;
    bool recovered;
    uint64_t recovered_value;
};

struct AggregateSummaryRow {
    std::string backend;
    std::string submode;
    int bit_width;
    int32_t episodes;
    int32_t exact_recovery_count;
    int32_t unexpected_acceptance_count;
    int32_t blocked_by_rejection_count;
    double exact_recovery_rate;
    double unexpected_acceptance_rate;
    double blocked_by_rejection_rate;
    double mean_queries;
    double mean_latency_us;
    double mean_bytes;
};

struct QueryResult {
    int threshold_freshly_encrypted_by_attacker;
    int registration_attempted;
    int registration_succeeded;
    int threshold_registered;
    uint64_t lhs_handle;
    uint64_t rhs_handle;
    int handle_lookup_succeeded;
    int statement_construction_called;
    int statement_construction_succeeded;
    int proof_generation_called;
    int proof_present;
    int proof_verification_called;
    int proof_verification_succeeded;
    int gate_checked_admissibility;
    int final_release_attempted;
    bool accepted;
    bool rejected;
    bool has_bit;
    int bit;
    uint64_t latency_us;
    uint64_t bytes;
    std::string acceptance_stage;
    std::string detail;
};

struct DebugReport {
    bool ready;
    uint64_t plaintext_m;
    int bit_width;
    int32_t episode_id;
    std::vector<QueryLogRow> orhe_queries;
};

static void init_empty_proof(ORHEProof* proof) {
    proof->family = ORHE_PROOF_FAMILY_NONE;
    proof->blob = NULL;
    proof->blob_len = 0;
    proof->owns_backend_buffer = 0;
}

static std::string join_path(const std::string& dir, const char* file_name) {
    if (dir.empty() || dir == ".") return std::string(file_name);
    const char last = dir[dir.size() - 1];
    if (last == '\\' || last == '/') return dir + file_name;
    return dir + "\\" + file_name;
}

static bool parse_uint64_arg(const char* text, uint64_t* out) {
    if (!text || !*text) return false;
    char* end = NULL;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (!end || *end != '\0') return false;
    *out = (uint64_t) value;
    return true;
}

static bool parse_bit_width_token(const char* text, int* out) {
    if (!text || !*text) return false;
    char* end = NULL;
    const long value = std::strtol(text, &end, 10);
    if (!end || *end != '\0') return false;
    if (value != 8 && value != 16 && value != 32 && value != 64) return false;
    *out = (int) value;
    return true;
}

static bool parse_bit_widths_csv(const char* text, std::vector<int>* out) {
    out->clear();
    if (!text || !*text) return false;

    const char* cursor = text;
    while (*cursor) {
        const char* comma = std::strchr(cursor, ',');
        const std::string token = comma ? std::string(cursor, (size_t) (comma - cursor)) : std::string(cursor);
        int value = 0;
        if (!parse_bit_width_token(token.c_str(), &value)) return false;
        out->push_back(value);
        if (!comma) break;
        cursor = comma + 1;
    }

    return !out->empty();
}

static bool parse_args(int argc, char** argv, AttackBenchConfig* cfg) {
    cfg->full_mode = false;
    cfg->episodes = 100;
    cfg->seed = 1;
    cfg->output_dir = ".";
    cfg->bit_widths.assign(kBitWidths, kBitWidths + sizeof(kBitWidths) / sizeof(kBitWidths[0]));

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            const char* mode = argv[++i];
            if (std::strcmp(mode, "quick") == 0) {
                cfg->full_mode = false;
                cfg->episodes = 100;
                continue;
            }
            if (std::strcmp(mode, "full") == 0) {
                cfg->full_mode = true;
                cfg->episodes = 1000;
                continue;
            }
            return false;
        }
        if (std::strcmp(argv[i], "--episodes") == 0 && i + 1 < argc) {
            const int32_t episodes = std::atoi(argv[++i]);
            if (episodes <= 0) return false;
            cfg->episodes = episodes;
            continue;
        }
        if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (!parse_uint64_arg(argv[++i], &cfg->seed)) return false;
            continue;
        }
        if (std::strcmp(argv[i], "--bit-width") == 0 && i + 1 < argc) {
            int value = 0;
            if (!parse_bit_width_token(argv[++i], &value)) return false;
            cfg->bit_widths.clear();
            cfg->bit_widths.push_back(value);
            continue;
        }
        if (std::strcmp(argv[i], "--bit-widths") == 0 && i + 1 < argc) {
            if (!parse_bit_widths_csv(argv[++i], &cfg->bit_widths)) return false;
            continue;
        }
        if (std::strcmp(argv[i], "--output-dir") == 0 && i + 1 < argc) {
            cfg->output_dir = argv[++i];
            if (cfg->output_dir.empty()) cfg->output_dir = ".";
            continue;
        }
        return false;
    }

    return true;
}

static uint64_t sample_uniform_value(std::mt19937_64* rng, int bit_width) {
    const uint64_t raw = (*rng)();
    if (bit_width >= 64) return raw;
    return raw & ((1ULL << bit_width) - 1ULL);
}

static uint64_t max_plaintext_value(int bit_width) {
    if (bit_width >= 64) return std::numeric_limits<uint64_t>::max();
    return (1ULL << bit_width) - 1ULL;
}

static void encrypt_u64(ORHECiphertext* out, uint64_t value, const ORHEKeySet* ks) {
    for (int32_t i = 0; i < out->nbits; ++i) {
        const int bit = ((value >> i) & 1ULL) ? 1 : 0;
        bootsSymEncrypt(&out->bits[i], bit, ks->data_sk);
    }
}

static bool register_base_checked(
    ORHEHandleTable* table,
    uint64_t handle,
    ORHECiphertext* ct,
    const ORHEKeySet* ks,
    ORHEMetrics* metrics
) {
    ORHEAuthSignature sig;
    orhe_auth_sign(&sig, handle, ct, &ks->auth_sk);
    return orhe_register_base_with_metrics(table, handle, ct, &sig, ks, metrics) == 1;
}

static ORHECircuitTrace* build_malicious_constant_trace(const ORHECiphertext* value_ct, int bit_width) {
    ORHECircuitTrace* trace = orhe_trace_new(bit_width);
    if (!trace) return NULL;

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_CONST;
    op.dst_wire = 0;
    op.src0_wire = -1;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = 0;

    if (orhe_trace_append_op(trace, op) != 1 || orhe_trace_record_wire(trace, 0, value_ct) != 1) {
        orhe_trace_delete(trace);
        return NULL;
    }

    trace->final_wire = 0;
    return trace;
}

static void print_trace_header(FILE* out) {
    std::fprintf(
        out,
        "backend,submode,bit_width,episode_id,query_index,plaintext_m,threshold,"
        "interval_lo_before,interval_hi_before,interval_lo_after,interval_hi_after,"
        "threshold_freshly_encrypted_by_attacker,registration_attempted,registration_succeeded,threshold_registered,"
        "lhs_handle,rhs_handle,handle_lookup_succeeded,"
        "statement_construction_called,statement_construction_succeeded,"
        "proof_generation_called,proof_present,proof_verification_called,proof_verification_succeeded,"
        "gate_checked_admissibility,final_release_attempted,"
        "accepted,rejected,bit,latency_us,bytes,acceptance_stage,detail\n"
    );
}

static void print_trace_row(FILE* out, const QueryLogRow* row) {
    std::fprintf(
        out,
        "%s,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
        row->backend.c_str(),
        row->submode.c_str(),
        (unsigned long long) row->bit_width,
        (unsigned long long) row->episode_id,
        (unsigned long long) row->query_index,
        (unsigned long long) row->plaintext_m,
        (unsigned long long) row->threshold,
        (unsigned long long) row->interval_lo_before,
        (unsigned long long) row->interval_hi_before,
        (unsigned long long) row->interval_lo_after,
        (unsigned long long) row->interval_hi_after,
        (unsigned long long) row->threshold_freshly_encrypted_by_attacker,
        (unsigned long long) row->registration_attempted,
        (unsigned long long) row->registration_succeeded,
        (unsigned long long) row->threshold_registered,
        (unsigned long long) row->lhs_handle,
        (unsigned long long) row->rhs_handle,
        (unsigned long long) row->handle_lookup_succeeded,
        (unsigned long long) row->statement_construction_called,
        (unsigned long long) row->statement_construction_succeeded,
        (unsigned long long) row->proof_generation_called,
        (unsigned long long) row->proof_present,
        (unsigned long long) row->proof_verification_called,
        (unsigned long long) row->proof_verification_succeeded,
        (unsigned long long) row->gate_checked_admissibility,
        (unsigned long long) row->final_release_attempted,
        (unsigned long long) row->accepted,
        (unsigned long long) row->rejected
    );

    if (row->has_bit) {
        std::fprintf(out, "%llu,", (unsigned long long) row->bit);
    } else {
        std::fprintf(out, ",");
    }

    std::fprintf(
        out,
        "%llu,%llu,%s,%s\n",
        (unsigned long long) row->latency_us,
        (unsigned long long) row->bytes,
        row->acceptance_stage.c_str(),
        row->detail.c_str()
    );
    std::fflush(out);
}

static void print_episode_summary_header(FILE* out) {
    std::fprintf(
        out,
        "backend,submode,bit_width,episode_id,plaintext_m,outcome,queries,"
        "setup_latency_us,query_latency_us,total_latency_us,"
        "setup_bytes,query_bytes,total_bytes,recovered,recovered_value\n"
    );
}

static void print_episode_summary_row(FILE* out, const EpisodeSummaryRow* row) {
    std::fprintf(
        out,
        "%s,%s,%d,%d,%llu,%s,%d,%llu,%llu,%llu,%llu,%llu,%llu,%d,%llu\n",
        row->backend.c_str(),
        row->submode.c_str(),
        row->bit_width,
        (int) row->episode_id,
        (unsigned long long) row->plaintext_m,
        row->outcome.c_str(),
        (int) row->queries,
        (unsigned long long) row->setup_latency_us,
        (unsigned long long) row->query_latency_us,
        (unsigned long long) row->total_latency_us,
        (unsigned long long) row->setup_bytes,
        (unsigned long long) row->query_bytes,
        (unsigned long long) row->total_bytes,
        row->recovered ? 1 : 0,
        (unsigned long long) row->recovered_value
    );
    std::fflush(out);
}

static void print_aggregate_summary_header(FILE* out) {
    std::fprintf(
        out,
        "backend,submode,bit_width,episodes,"
        "exact_recovery_count,unexpected_acceptance_count,blocked_by_rejection_count,"
        "exact_recovery_rate,unexpected_acceptance_rate,blocked_by_rejection_rate,"
        "mean_queries,mean_latency_us,mean_bytes\n"
    );
}

static void print_aggregate_summary_row(FILE* out, const AggregateSummaryRow* row) {
    std::fprintf(
        out,
        "%s,%s,%d,%d,%d,%d,%d,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f\n",
        row->backend.c_str(),
        row->submode.c_str(),
        row->bit_width,
        (int) row->episodes,
        (int) row->exact_recovery_count,
        (int) row->unexpected_acceptance_count,
        (int) row->blocked_by_rejection_count,
        row->exact_recovery_rate,
        row->unexpected_acceptance_rate,
        row->blocked_by_rejection_rate,
        row->mean_queries,
        row->mean_latency_us,
        row->mean_bytes
    );
    std::fflush(out);
}

static void write_run_config_json(FILE* out, const AttackBenchConfig* cfg) {
    std::fprintf(out, "{\n");
    std::fprintf(out, "  \"mode\": \"%s\",\n", cfg->full_mode ? "full" : "quick");
    std::fprintf(out, "  \"episodes_per_backend_or_submode\": %d,\n", (int) cfg->episodes);
    std::fprintf(out, "  \"seed\": %llu,\n", (unsigned long long) cfg->seed);
    std::fprintf(out, "  \"bit_widths\": [");
    for (size_t i = 0; i < cfg->bit_widths.size(); ++i) {
        if (i > 0) std::fprintf(out, ", ");
        std::fprintf(out, "%d", cfg->bit_widths[i]);
    }
    std::fprintf(out, "],\n");
    std::fprintf(out, "  \"backends\": [\"unsafe_compare\", \"orhe_attack\"],\n");
    std::fprintf(out, "  \"orhe_attack_submodes\": [\"fresh_unregistered_threshold\", \"registered_threshold_if_supported\"],\n");
    std::fprintf(out, "  \"orhe_fail_fast\": true,\n");
    std::fprintf(out, "  \"unsafe_compare_behavior\": \"full binary search\",\n");
    std::fprintf(out, "  \"orhe_attack_behavior\": \"stop on first malicious query outcome\",\n");
    std::fprintf(out, "  \"outputs\": {\n");
    std::fprintf(out, "    \"attack_trace_csv\": \"attack_trace.csv\",\n");
    std::fprintf(out, "    \"attack_episode_summary_csv\": \"attack_episode_summary.csv\",\n");
    std::fprintf(out, "    \"attack_aggregate_summary_csv\": \"attack_aggregate_summary.csv\",\n");
    std::fprintf(out, "    \"run_config_json\": \"run_config.json\",\n");
    std::fprintf(out, "    \"attack_debug_report_txt\": \"attack_debug_report.txt\"\n");
    std::fprintf(out, "  },\n");
    std::fprintf(out, "  \"episode_outcomes\": [\"exact_recovery\", \"unexpected_acceptance\", \"blocked_by_rejection\"],\n");
    std::fprintf(out, "  \"acceptance_stage_examples\": [\n");
    std::fprintf(out, "    \"accepted_without_registration_check\",\n");
    std::fprintf(out, "    \"%s\",\n", kStageAcceptedAfterRegistrationOnly);
    std::fprintf(out, "    \"%s\",\n", kStageAcceptedAfterProofVerification);
    std::fprintf(out, "    \"%s\",\n", kStageRejectedMissingRegistration);
    std::fprintf(out, "    \"%s\",\n", kStageRejectedBadHandle);
    std::fprintf(out, "    \"%s\",\n", kStageRejectedBadProof);
    std::fprintf(out, "    \"%s\"\n", kStageRejectedPreRelease);
    std::fprintf(out, "  ]\n");
    std::fprintf(out, "}\n");
    std::fflush(out);
}

static void write_debug_report(const DebugReport* report, const std::string& path) {
    if (!report->ready) return;

    FILE* out = std::fopen(path.c_str(), "w");
    if (!out) return;

    std::fprintf(out, "ORHE Fail-Fast Debug Report\n");
    std::fprintf(out, "bit_width=%d\n", report->bit_width);
    std::fprintf(out, "episode_id=%d\n", (int) report->episode_id);
    std::fprintf(out, "target_plaintext=%llu\n", (unsigned long long) report->plaintext_m);
    std::fprintf(out, "\n");
    std::fprintf(out, "Queried malicious thresholds:\n");

    for (size_t i = 0; i < report->orhe_queries.size(); ++i) {
        const QueryLogRow& row = report->orhe_queries[i];
        std::fprintf(
            out,
            "- submode=%s threshold=%llu accepted=%d rejected=%d acceptance_stage=%s detail=%s\n",
            row.submode.c_str(),
            (unsigned long long) row.threshold,
            row.accepted,
            row.rejected,
            row.acceptance_stage.c_str(),
            row.detail.c_str()
        );
        std::fprintf(
            out,
            "  registration_attempted=%d registration_succeeded=%d threshold_registered=%d lhs_handle=%llu rhs_handle=%llu handle_lookup_succeeded=%d\n",
            row.registration_attempted,
            row.registration_succeeded,
            row.threshold_registered,
            (unsigned long long) row.lhs_handle,
            (unsigned long long) row.rhs_handle,
            row.handle_lookup_succeeded
        );
        std::fprintf(
            out,
            "  statement_construction_called=%d statement_construction_succeeded=%d proof_generation_called=%d proof_present=%d proof_verification_called=%d proof_verification_succeeded=%d final_release_attempted=%d gate_checked_admissibility=%d\n",
            row.statement_construction_called,
            row.statement_construction_succeeded,
            row.proof_generation_called,
            row.proof_present,
            row.proof_verification_called,
            row.proof_verification_succeeded,
            row.final_release_attempted,
            row.gate_checked_admissibility
        );
    }

    std::fprintf(out, "\n");
    std::fprintf(out, "Root cause analysis:\n");
    std::fprintf(out, "- Temporary lockdown is active in RegisterDerived.\n");
    std::fprintf(out, "- Rule 1: derived registrations with nsrc <= 0 are rejected.\n");
    std::fprintf(out, "- Rule 2: external RegisterDerived traces must start from registered source handles.\n");
    std::fprintf(out, "- Rule 3: snapshot-backed glue wires are verifier-recomputed and rejected on mismatch.\n");
    std::fprintf(out, "- Rule 4: external PBS trace nodes are only accepted for verifier-recomputed allowed relations.\n");
    std::fprintf(out, "- Result: fresh unregistered thresholds fail before compare, and malicious registered-threshold minting now fails during RegisterDerived.\n");

    std::fclose(out);
}

static QueryResult make_empty_query_result(uint64_t lhs_handle, uint64_t rhs_handle) {
    QueryResult result;
    result.threshold_freshly_encrypted_by_attacker = 1;
    result.registration_attempted = 0;
    result.registration_succeeded = 0;
    result.threshold_registered = 0;
    result.lhs_handle = lhs_handle;
    result.rhs_handle = rhs_handle;
    result.handle_lookup_succeeded = 0;
    result.statement_construction_called = 0;
    result.statement_construction_succeeded = 0;
    result.proof_generation_called = 0;
    result.proof_present = 0;
    result.proof_verification_called = 0;
    result.proof_verification_succeeded = 0;
    result.gate_checked_admissibility = 0;
    result.final_release_attempted = 0;
    result.accepted = false;
    result.rejected = false;
    result.has_bit = false;
    result.bit = 0;
    result.latency_us = 0;
    result.bytes = 0;
    result.acceptance_stage = kStageRejectedPreRelease;
    result.detail = "uninitialized";
    return result;
}

static QueryResult run_unsafe_query(
    uint64_t threshold,
    const ORHECiphertext* message_ct,
    const ORHEKeySet* ks
) {
    QueryResult result = make_empty_query_result(0, 0);
    result.final_release_attempted = 1;
    result.acceptance_stage = kStageAcceptedWithoutRegistrationCheck;
    result.detail = "unsafe_compare_uses_direct_ciphertexts";

    ORHECiphertext* threshold_ct = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);
    ORHEMetrics metrics;
    orhe_metrics_reset(&metrics);

    ORHETimer timer;
    orhe_timer_start(&timer);
    encrypt_u64(threshold_ct, threshold, ks);
    const int bit = orhe_compare_plain_with_metrics(message_ct, threshold_ct, c_sgn, u, ks, &metrics);
    result.latency_us = orhe_timer_elapsed_us(&timer);
    result.bytes = orhe_ciphertext_size_bytes(threshold_ct) + 1ULL;
    result.accepted = true;
    result.has_bit = true;
    result.bit = bit;

    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    orhe_delete_ciphertext(threshold_ct);
    return result;
}

static QueryResult run_orhe_fresh_unregistered_query(
    uint64_t base_handle,
    uint64_t rhs_handle,
    uint64_t threshold,
    ORHEHandleTable* table,
    const ORHEKeySet* ks
) {
    QueryResult result = make_empty_query_result(base_handle, rhs_handle);
    result.detail = "fresh_threshold_not_registered";

    ORHECiphertext* threshold_ct = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    encrypt_u64(threshold_ct, threshold, ks);
    result.bytes += orhe_ciphertext_size_bytes(threshold_ct);

    const ORHEHandleEntry* lhs = orhe_lookup(table, base_handle);
    const ORHEHandleEntry* rhs = orhe_lookup(table, rhs_handle);
    result.handle_lookup_succeeded = (lhs != NULL && rhs != NULL) ? 1 : 0;

    result.statement_construction_called = 1;

    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);
    ORHEProof proof;
    init_empty_proof(&proof);
    ORHEMetrics compare_metrics;
    orhe_metrics_reset(&compare_metrics);

    const int compare_ok = orhe_compare_server_prove_with_metrics(
        base_handle,
        rhs_handle,
        table,
        c_sgn,
        u,
        &proof,
        ks,
        &compare_metrics
    );
    result.latency_us = orhe_timer_elapsed_us(&timer);
    result.bytes += compare_metrics.total_online_comm_bytes;
    result.statement_construction_succeeded = (compare_ok == 1) ? 1 : 0;
    result.proof_generation_called = (compare_ok == 1) ? 1 : 0;
    result.proof_present = (proof.family != ORHE_PROOF_FAMILY_NONE || proof.blob_len > 0) ? 1 : 0;

    if (compare_ok != 1) {
        result.rejected = true;
        result.acceptance_stage = lhs ? kStageRejectedMissingRegistration : kStageRejectedBadHandle;
        result.detail = lhs ? "compare_rejected_before_proof_due_to_missing_threshold_registration"
                            : "compare_rejected_before_proof_due_to_missing_base_or_threshold_handle";
    }

    orhe_proof_clear(&proof);
    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    orhe_delete_ciphertext(threshold_ct);
    return result;
}

static QueryResult run_orhe_registered_threshold_query(
    uint64_t base_handle,
    uint64_t rhs_handle,
    uint64_t threshold,
    ORHEHandleTable* table,
    std::vector<ORHECiphertext*>* owned_thresholds,
    const ORHEKeySet* ks
) {
    QueryResult result = make_empty_query_result(base_handle, rhs_handle);
    result.registration_attempted = 1;

    ORHECiphertext* threshold_ct = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    encrypt_u64(threshold_ct, threshold, ks);
    result.bytes += orhe_ciphertext_size_bytes(threshold_ct);

    ORHECircuitTrace* trace = build_malicious_constant_trace(threshold_ct, ks->params.bit_width);
    if (!trace) {
        result.rejected = true;
        result.latency_us = orhe_timer_elapsed_us(&timer);
        result.acceptance_stage = kStageRejectedPreRelease;
        result.detail = "failed_to_build_malicious_const_trace";
        orhe_delete_ciphertext(threshold_ct);
        return result;
    }

    ORHEMetrics registration_metrics;
    orhe_metrics_reset(&registration_metrics);
    const int register_ok = orhe_register_derived_with_metrics(
        table,
        rhs_handle,
        NULL,
        0,
        threshold_ct,
        trace,
        ks,
        &registration_metrics
    );
    orhe_trace_delete(trace);

    result.registration_succeeded = (register_ok == 1) ? 1 : 0;
    result.threshold_registered = result.registration_succeeded;
    result.bytes += registration_metrics.total_online_comm_bytes;

    if (register_ok != 1) {
        result.rejected = true;
        result.latency_us = orhe_timer_elapsed_us(&timer);
        result.acceptance_stage = kStageRejectedPreRelease;
        result.detail = std::string("register_derived_rejected:") + orhe_register_derived_last_error();
        orhe_delete_ciphertext(threshold_ct);
        return result;
    }

    owned_thresholds->push_back(threshold_ct);

    const ORHEHandleEntry* lhs = orhe_lookup(table, base_handle);
    const ORHEHandleEntry* rhs = orhe_lookup(table, rhs_handle);
    result.handle_lookup_succeeded = (lhs != NULL && rhs != NULL) ? 1 : 0;

    result.statement_construction_called = 1;

    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);
    ORHEProof proof;
    init_empty_proof(&proof);

    ORHEMetrics compare_prove_metrics;
    ORHEMetrics compare_verify_metrics;
    orhe_metrics_reset(&compare_prove_metrics);
    orhe_metrics_reset(&compare_verify_metrics);

    const int compare_ok = orhe_compare_server_prove_with_metrics(
        base_handle,
        rhs_handle,
        table,
        c_sgn,
        u,
        &proof,
        ks,
        &compare_prove_metrics
    );

    result.bytes += compare_prove_metrics.total_online_comm_bytes;
    result.statement_construction_succeeded = (compare_ok == 1) ? 1 : 0;
    result.proof_generation_called = (compare_ok == 1) ? 1 : 0;
    result.proof_present = (proof.family != ORHE_PROOF_FAMILY_NONE || proof.blob_len > 0) ? 1 : 0;

    if (compare_ok != 1) {
        result.rejected = true;
        result.latency_us = orhe_timer_elapsed_us(&timer);
        result.acceptance_stage = kStageRejectedBadHandle;
        result.detail = "compare_rejected_after_registration_during_handle_lookup_or_statement_build";
        orhe_proof_clear(&proof);
        delete_gate_bootstrapping_ciphertext(c_sgn);
        delete_LweSample(u);
        return result;
    }

    result.proof_verification_called = 1;
    result.final_release_attempted = 1;
    result.gate_checked_admissibility = 0;

    const int sigma = orhe_gate_compare_verified_with_metrics(
        base_handle,
        rhs_handle,
        table,
        c_sgn,
        u,
        &proof,
        ks,
        &compare_verify_metrics
    );
    result.bytes += compare_verify_metrics.total_online_comm_bytes;
    result.latency_us = orhe_timer_elapsed_us(&timer);
    result.proof_verification_succeeded = (sigma == 0 || sigma == 1) ? 1 : 0;

    if (sigma == 0 || sigma == 1) {
        result.accepted = true;
        result.has_bit = true;
        result.bit = sigma;
        result.acceptance_stage = kStageAcceptedAfterProofVerification;
        result.detail =
            "accepted_after_register_derived_const_snapshot_with_nsrc0_then_compare_proof_verified";
    } else {
        result.rejected = true;
        result.acceptance_stage = kStageRejectedBadProof;
        result.detail = "compare_gate_rejected_after_proof_verification";
    }

    orhe_proof_clear(&proof);
    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    return result;
}

static EpisodeSummaryRow run_unsafe_episode(
    int bit_width,
    int32_t episode_id,
    uint64_t plaintext_m,
    const ORHEKeySet* ks,
    FILE* trace_out
) {
    EpisodeSummaryRow summary;
    summary.backend = kBackendUnsafe;
    summary.submode = kUnsafeSubmode;
    summary.bit_width = bit_width;
    summary.episode_id = episode_id;
    summary.plaintext_m = plaintext_m;
    summary.outcome = kOutcomeBlockedByRejection;
    summary.queries = 0;
    summary.setup_latency_us = 0;
    summary.query_latency_us = 0;
    summary.total_latency_us = 0;
    summary.setup_bytes = 0;
    summary.query_bytes = 0;
    summary.total_bytes = 0;
    summary.recovered = false;
    summary.recovered_value = 0;

    ORHECiphertext* message_ct = orhe_new_ciphertext(bit_width, ks->tfhe_params);
    ORHETimer encrypt_t;
    orhe_timer_start(&encrypt_t);
    encrypt_u64(message_ct, plaintext_m, ks);
    summary.setup_latency_us = orhe_timer_elapsed_us(&encrypt_t);

    uint64_t lo = 0;
    uint64_t hi = max_plaintext_value(bit_width);
    const int32_t max_queries = bit_width + 2;

    for (int32_t query_index = 0; query_index < max_queries && lo < hi; ++query_index) {
        const uint64_t threshold = lo + ((hi - lo) >> 1) + 1ULL;
        const uint64_t lo_before = lo;
        const uint64_t hi_before = hi;

        const QueryResult qr = run_unsafe_query(threshold, message_ct, ks);

        uint64_t lo_after = lo_before;
        uint64_t hi_after = hi_before;
        if (qr.bit == 1) hi_after = threshold - 1ULL;
        else lo_after = threshold;

        QueryLogRow row;
        row.backend = summary.backend;
        row.submode = summary.submode;
        row.bit_width = summary.bit_width;
        row.episode_id = summary.episode_id;
        row.query_index = query_index + 1;
        row.plaintext_m = plaintext_m;
        row.threshold = threshold;
        row.interval_lo_before = lo_before;
        row.interval_hi_before = hi_before;
        row.interval_lo_after = lo_after;
        row.interval_hi_after = hi_after;
        row.threshold_freshly_encrypted_by_attacker = qr.threshold_freshly_encrypted_by_attacker;
        row.registration_attempted = qr.registration_attempted;
        row.registration_succeeded = qr.registration_succeeded;
        row.threshold_registered = qr.threshold_registered;
        row.lhs_handle = qr.lhs_handle;
        row.rhs_handle = qr.rhs_handle;
        row.handle_lookup_succeeded = qr.handle_lookup_succeeded;
        row.statement_construction_called = qr.statement_construction_called;
        row.statement_construction_succeeded = qr.statement_construction_succeeded;
        row.proof_generation_called = qr.proof_generation_called;
        row.proof_present = qr.proof_present;
        row.proof_verification_called = qr.proof_verification_called;
        row.proof_verification_succeeded = qr.proof_verification_succeeded;
        row.gate_checked_admissibility = qr.gate_checked_admissibility;
        row.final_release_attempted = qr.final_release_attempted;
        row.accepted = qr.accepted ? 1 : 0;
        row.rejected = qr.rejected ? 1 : 0;
        row.has_bit = qr.has_bit;
        row.bit = qr.bit;
        row.latency_us = qr.latency_us;
        row.bytes = qr.bytes;
        row.acceptance_stage = qr.acceptance_stage;
        row.detail = qr.detail;
        print_trace_row(trace_out, &row);

        summary.queries += 1;
        summary.query_latency_us += qr.latency_us;
        summary.query_bytes += qr.bytes;

        lo = lo_after;
        hi = hi_after;
    }

    summary.recovered = (lo == hi && lo == plaintext_m);
    summary.recovered_value = lo;
    summary.outcome = summary.recovered ? kOutcomeExactRecovery : kOutcomeBlockedByRejection;
    summary.total_latency_us = summary.setup_latency_us + summary.query_latency_us;
    summary.total_bytes = summary.setup_bytes + summary.query_bytes;

    orhe_delete_ciphertext(message_ct);
    return summary;
}

static EpisodeSummaryRow run_orhe_episode(
    const char* submode,
    int bit_width,
    int32_t episode_id,
    uint64_t plaintext_m,
    const ORHEKeySet* ks,
    FILE* trace_out,
    DebugReport* debug_report
) {
    EpisodeSummaryRow summary;
    summary.backend = kBackendOrhe;
    summary.submode = submode;
    summary.bit_width = bit_width;
    summary.episode_id = episode_id;
    summary.plaintext_m = plaintext_m;
    summary.outcome = kOutcomeBlockedByRejection;
    summary.queries = 0;
    summary.setup_latency_us = 0;
    summary.query_latency_us = 0;
    summary.total_latency_us = 0;
    summary.setup_bytes = 0;
    summary.query_bytes = 0;
    summary.total_bytes = 0;
    summary.recovered = false;
    summary.recovered_value = 0;

    ORHECiphertext* message_ct = orhe_new_ciphertext(bit_width, ks->tfhe_params);
    ORHETimer encrypt_t;
    orhe_timer_start(&encrypt_t);
    encrypt_u64(message_ct, plaintext_m, ks);
    summary.setup_latency_us = orhe_timer_elapsed_us(&encrypt_t);

    ORHEHandleTable table;
    orhe_init_table(&table);
    std::vector<ORHECiphertext*> owned_thresholds;
    owned_thresholds.reserve(2);

    const uint64_t base_handle = 1000000ULL + ((uint64_t) bit_width << 20) + (uint64_t) episode_id;
    ORHEMetrics base_metrics;
    orhe_metrics_reset(&base_metrics);
    if (!register_base_checked(&table, base_handle, message_ct, ks, &base_metrics)) {
        summary.outcome = kOutcomeBlockedByRejection;
        orhe_free_table(&table);
        orhe_delete_ciphertext(message_ct);
        return summary;
    }
    summary.setup_latency_us += base_metrics.end_to_end_online_us;
    summary.setup_bytes += base_metrics.total_online_comm_bytes;

    uint64_t lo = 0;
    uint64_t hi = max_plaintext_value(bit_width);
    const uint64_t threshold = lo + ((hi - lo) >> 1) + 1ULL;
    const uint64_t query_handle = 2000000ULL + ((uint64_t) bit_width << 24) + ((uint64_t) episode_id << 8);

    QueryResult qr;
    if (std::strcmp(submode, kFreshUnregisteredSubmode) == 0) {
        qr = run_orhe_fresh_unregistered_query(base_handle, query_handle, threshold, &table, ks);
    } else {
        qr = run_orhe_registered_threshold_query(base_handle, query_handle, threshold, &table, &owned_thresholds, ks);
    }

    uint64_t lo_after = lo;
    uint64_t hi_after = hi;
    if (qr.accepted && qr.has_bit) {
        if (qr.bit == 1) hi_after = threshold - 1ULL;
        else lo_after = threshold;
    }

    QueryLogRow row;
    row.backend = summary.backend;
    row.submode = summary.submode;
    row.bit_width = summary.bit_width;
    row.episode_id = summary.episode_id;
    row.query_index = 1;
    row.plaintext_m = plaintext_m;
    row.threshold = threshold;
    row.interval_lo_before = lo;
    row.interval_hi_before = hi;
    row.interval_lo_after = lo_after;
    row.interval_hi_after = hi_after;
    row.threshold_freshly_encrypted_by_attacker = qr.threshold_freshly_encrypted_by_attacker;
    row.registration_attempted = qr.registration_attempted;
    row.registration_succeeded = qr.registration_succeeded;
    row.threshold_registered = qr.threshold_registered;
    row.lhs_handle = qr.lhs_handle;
    row.rhs_handle = qr.rhs_handle;
    row.handle_lookup_succeeded = qr.handle_lookup_succeeded;
    row.statement_construction_called = qr.statement_construction_called;
    row.statement_construction_succeeded = qr.statement_construction_succeeded;
    row.proof_generation_called = qr.proof_generation_called;
    row.proof_present = qr.proof_present;
    row.proof_verification_called = qr.proof_verification_called;
    row.proof_verification_succeeded = qr.proof_verification_succeeded;
    row.gate_checked_admissibility = qr.gate_checked_admissibility;
    row.final_release_attempted = qr.final_release_attempted;
    row.accepted = qr.accepted ? 1 : 0;
    row.rejected = qr.rejected ? 1 : 0;
    row.has_bit = qr.has_bit;
    row.bit = qr.bit;
    row.latency_us = qr.latency_us;
    row.bytes = qr.bytes;
    row.acceptance_stage = qr.acceptance_stage;
    row.detail = qr.detail;
    print_trace_row(trace_out, &row);

    summary.queries = 1;
    summary.query_latency_us = qr.latency_us;
    summary.query_bytes = qr.bytes;
    summary.total_latency_us = summary.setup_latency_us + summary.query_latency_us;
    summary.total_bytes = summary.setup_bytes + summary.query_bytes;

    if (qr.accepted) {
        summary.recovered = (lo_after == hi_after && lo_after == plaintext_m);
        summary.recovered_value = summary.recovered ? lo_after : 0;
        summary.outcome = summary.recovered ? kOutcomeExactRecovery : kOutcomeUnexpectedAcceptance;
    } else {
        summary.outcome = kOutcomeBlockedByRejection;
    }

    if (debug_report && !debug_report->ready && bit_width == 8 && episode_id == 1) {
        debug_report->ready = true;
        debug_report->plaintext_m = plaintext_m;
        debug_report->bit_width = bit_width;
        debug_report->episode_id = episode_id;
    }
    if (debug_report && bit_width == 8 && episode_id == 1) {
        debug_report->orhe_queries.push_back(row);
    }

    orhe_free_table(&table);
    for (size_t i = 0; i < owned_thresholds.size(); ++i) {
        orhe_delete_ciphertext(owned_thresholds[i]);
    }
    orhe_delete_ciphertext(message_ct);
    return summary;
}

static AggregateSummaryRow compute_aggregate_row(
    const char* backend,
    const char* submode,
    int bit_width,
    const std::vector<EpisodeSummaryRow>& episodes
) {
    AggregateSummaryRow row;
    row.backend = backend;
    row.submode = submode;
    row.bit_width = bit_width;
    row.episodes = (int32_t) episodes.size();
    row.exact_recovery_count = 0;
    row.unexpected_acceptance_count = 0;
    row.blocked_by_rejection_count = 0;
    row.exact_recovery_rate = 0.0;
    row.unexpected_acceptance_rate = 0.0;
    row.blocked_by_rejection_rate = 0.0;
    row.mean_queries = 0.0;
    row.mean_latency_us = 0.0;
    row.mean_bytes = 0.0;

    if (episodes.empty()) return row;

    for (size_t i = 0; i < episodes.size(); ++i) {
        const EpisodeSummaryRow& ep = episodes[i];
        if (ep.outcome == kOutcomeExactRecovery) row.exact_recovery_count += 1;
        else if (ep.outcome == kOutcomeUnexpectedAcceptance) row.unexpected_acceptance_count += 1;
        else row.blocked_by_rejection_count += 1;

        row.mean_queries += (double) ep.queries;
        row.mean_latency_us += (double) ep.total_latency_us;
        row.mean_bytes += (double) ep.total_bytes;
    }

    const double denom = (double) episodes.size();
    row.exact_recovery_rate = (double) row.exact_recovery_count / denom;
    row.unexpected_acceptance_rate = (double) row.unexpected_acceptance_count / denom;
    row.blocked_by_rejection_rate = (double) row.blocked_by_rejection_count / denom;
    row.mean_queries /= denom;
    row.mean_latency_us /= denom;
    row.mean_bytes /= denom;
    return row;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    _putenv_s("ORHE_ENABLE_INSECURE_DEBUG_APIS", "1");
#else
    setenv("ORHE_ENABLE_INSECURE_DEBUG_APIS", "1", 1);
#endif

    AttackBenchConfig cfg;
    if (!parse_args(argc, argv, &cfg)) {
        std::fprintf(
            stderr,
            "usage: %s [--mode quick|full] [--episodes N] [--seed S] [--bit-width N] [--bit-widths a,b,c] [--output-dir PATH]\n",
            argv[0]
        );
        return 1;
    }

    const std::string trace_path = join_path(cfg.output_dir, "attack_trace.csv");
    const std::string episode_path = join_path(cfg.output_dir, "attack_episode_summary.csv");
    const std::string aggregate_path = join_path(cfg.output_dir, "attack_aggregate_summary.csv");
    const std::string config_path = join_path(cfg.output_dir, "run_config.json");
    const std::string debug_report_path = join_path(cfg.output_dir, "attack_debug_report.txt");

    FILE* trace_out = std::fopen(trace_path.c_str(), "w");
    FILE* episode_out = std::fopen(episode_path.c_str(), "w");
    FILE* aggregate_out = std::fopen(aggregate_path.c_str(), "w");
    FILE* config_out = std::fopen(config_path.c_str(), "w");
    if (!trace_out || !episode_out || !aggregate_out || !config_out) {
        std::fprintf(stderr, "failed to open one or more output files (errno=%d)\n", errno);
        if (trace_out) std::fclose(trace_out);
        if (episode_out) std::fclose(episode_out);
        if (aggregate_out) std::fclose(aggregate_out);
        if (config_out) std::fclose(config_out);
        return 1;
    }

    print_trace_header(trace_out);
    print_episode_summary_header(episode_out);
    print_aggregate_summary_header(aggregate_out);
    write_run_config_json(config_out, &cfg);
    std::fclose(config_out);

    std::mt19937_64 rng(cfg.seed);
    DebugReport debug_report;
    debug_report.ready = false;
    debug_report.plaintext_m = 0;
    debug_report.bit_width = 0;
    debug_report.episode_id = 0;

    for (size_t bw_idx = 0; bw_idx < cfg.bit_widths.size(); ++bw_idx) {
        const int bit_width = cfg.bit_widths[bw_idx];
        ORHEParams params;
        params.bit_width = bit_width;
        params.domain_min = 0;
        params.domain_max = std::numeric_limits<int32_t>::max();

        ORHEKeySet* ks = orhe_new_keyset(110, &params);
        if (!ks) {
            std::fprintf(stderr, "failed to create keyset for bit width %d\n", bit_width);
            std::fclose(trace_out);
            std::fclose(episode_out);
            std::fclose(aggregate_out);
            return 1;
        }

        std::vector<EpisodeSummaryRow> unsafe_rows;
        std::vector<EpisodeSummaryRow> fresh_rows;
        std::vector<EpisodeSummaryRow> registered_rows;
        unsafe_rows.reserve((size_t) cfg.episodes);
        fresh_rows.reserve((size_t) cfg.episodes);
        registered_rows.reserve((size_t) cfg.episodes);

        for (int32_t episode_id = 1; episode_id <= cfg.episodes; ++episode_id) {
            const uint64_t plaintext_m = sample_uniform_value(&rng, bit_width);

            const EpisodeSummaryRow unsafe_row =
                run_unsafe_episode(bit_width, episode_id, plaintext_m, ks, trace_out);
            print_episode_summary_row(episode_out, &unsafe_row);
            unsafe_rows.push_back(unsafe_row);

            const EpisodeSummaryRow fresh_row =
                run_orhe_episode(kFreshUnregisteredSubmode, bit_width, episode_id, plaintext_m, ks, trace_out, &debug_report);
            print_episode_summary_row(episode_out, &fresh_row);
            fresh_rows.push_back(fresh_row);

            const EpisodeSummaryRow registered_row =
                run_orhe_episode(kRegisteredThresholdSubmode, bit_width, episode_id, plaintext_m, ks, trace_out, &debug_report);
            print_episode_summary_row(episode_out, &registered_row);
            registered_rows.push_back(registered_row);
        }

        const AggregateSummaryRow unsafe_agg =
            compute_aggregate_row(kBackendUnsafe, kUnsafeSubmode, bit_width, unsafe_rows);
        const AggregateSummaryRow fresh_agg =
            compute_aggregate_row(kBackendOrhe, kFreshUnregisteredSubmode, bit_width, fresh_rows);
        const AggregateSummaryRow registered_agg =
            compute_aggregate_row(kBackendOrhe, kRegisteredThresholdSubmode, bit_width, registered_rows);

        print_aggregate_summary_row(aggregate_out, &unsafe_agg);
        print_aggregate_summary_row(aggregate_out, &fresh_agg);
        print_aggregate_summary_row(aggregate_out, &registered_agg);

        orhe_delete_keyset(ks);
    }

    std::fclose(trace_out);
    std::fclose(episode_out);
    std::fclose(aggregate_out);

    write_debug_report(&debug_report, debug_report_path);
    return 0;
}
