#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "orhe.h"
#include "orhe_metrics.h"

struct ThresholdBenchConfig {
    std::vector<int32_t> batch_sizes;
    std::string csv_path;
};

struct ThresholdBenchRow {
    const char* label;
    const char* mode;
    int32_t batch_size;
    int32_t num_comparisons;
    ORHEMetrics metrics;
};

static void init_empty_proof(ORHEProof* p) {
    p->family = ORHE_PROOF_FAMILY_NONE;
    p->blob = NULL;
    p->blob_len = 0;
    p->owns_backend_buffer = 0;
}

static bool parse_int32_arg(const char* text, int32_t* out) {
    char* end = NULL;
    long v = std::strtol(text, &end, 10);
    if (!text || !*text || !end || *end != '\0') return false;
    if (v <= 0 || v > 1000000L) return false;
    *out = (int32_t) v;
    return true;
}

static bool parse_batch_sizes_csv(const char* text, std::vector<int32_t>* out) {
    if (!text || !*text) return false;

    out->clear();
    const char* cursor = text;
    while (*cursor) {
        const char* comma = std::strchr(cursor, ',');
        std::string token = comma ? std::string(cursor, (size_t) (comma - cursor)) : std::string(cursor);
        int32_t value = 0;
        if (!parse_int32_arg(token.c_str(), &value)) return false;
        out->push_back(value);
        if (!comma) break;
        cursor = comma + 1;
    }

    return !out->empty();
}

static bool parse_args(int argc, char** argv, ThresholdBenchConfig* cfg) {
    cfg->batch_sizes.clear();
    cfg->batch_sizes.push_back(8);
    cfg->batch_sizes.push_back(16);
    cfg->batch_sizes.push_back(32);
    cfg->batch_sizes.push_back(64);
    cfg->batch_sizes.push_back(128);
    cfg->csv_path.clear();

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--batch-size") == 0 && i + 1 < argc) {
            int32_t value = 0;
            if (!parse_int32_arg(argv[++i], &value)) return false;
            cfg->batch_sizes.clear();
            cfg->batch_sizes.push_back(value);
            continue;
        }

        if (std::strcmp(argv[i], "--batch-sizes") == 0 && i + 1 < argc) {
            if (!parse_batch_sizes_csv(argv[++i], &cfg->batch_sizes)) return false;
            continue;
        }

        if (std::strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            cfg->csv_path = argv[++i];
            continue;
        }

        return false;
    }

    return true;
}

static bool register_base_checked(
    ORHEHandleTable* H,
    uint64_t handle,
    ORHECiphertext* ct,
    const ORHEKeySet* ks
) {
    ORHEAuthSignature sig;
    orhe_auth_sign(&sig, handle, ct, &ks->auth_sk);
    return orhe_register_base(H, handle, ct, &sig, ks) == 1;
}

static std::vector<uint32_t> build_dataset(int32_t batch_size) {
    std::vector<uint32_t> values((size_t) batch_size, 0);
    for (int32_t i = 0; i < batch_size; ++i) {
        values[(size_t) i] = (uint32_t) ((37 * i + 11) % 96);
    }
    return values;
}

static uint64_t input_ciphertext_bytes(
    const std::vector<ORHECiphertext*>& values,
    const ORHECiphertext* threshold_ct
) {
    uint64_t total = 0;
    for (size_t i = 0; i < values.size(); ++i) {
        total += orhe_ciphertext_size_bytes(values[i]);
    }
    total += orhe_ciphertext_size_bytes(threshold_ct);
    return total;
}

static void delete_ciphertext_vector(std::vector<ORHECiphertext*>* values) {
    for (size_t i = 0; i < values->size(); ++i) {
        orhe_delete_ciphertext((*values)[i]);
    }
    values->clear();
}

static void print_bench_csv_header(FILE* f) {
    // Timing definitions:
    // - exec_tfhe_us counts compare-execution TFHE only.
    // - verify_tfhe_us counts verifier-side TFHE recomputation only; it is zero for the
    //   default trace-backed compare proof because verification checks proof material
    //   instead of rerunning the compare circuit in TFHE.
    // - prover_us / verifier_us count ORHE proof generation / proof verification only.
    // - end_to_end_online_us is the sum of measured online compare calls only; it excludes
    //   key generation, plaintext generation, encryption, base registration, and CSV I/O.
    // - compare_tfhe_us / compare_prover_us / compare_verifier_us are the compare-path
    //   totals. For the default trace-backed compare proof, compare_tfhe_us is execution
    //   TFHE only and compare_verifier_us is proof verification only.
    // - exec_subtraction_us is execution-side bit-sliced subtraction only.
    // - exec_signbit_pbs_us is execution-side sign-bit PBS only; it is decomposed into
    //   accum_init_us + blind_rotate_us + extract_us + exec_internal_ks_us.
    // - exec_final_cmp_ks_us is the execution-side key switch from the sign-bit output
    //   into the compare domain.
    // - verify_subtraction_us and verify_final_cmp_ks_us are verifier-side TFHE
    //   recomputations only; they remain zero for the default trace-backed compare proof.
    // - accum_init_us / blind_rotate_us / extract_us are execution-side sign-bit PBS
    //   subcomponents only. They are batch totals across all comparisons in the row.
    //
    // Byte-count definitions:
    // - proof_size_bytes counts transmitted proof blobs, including the compare trace-backed
    //   checkpoint bundle plus the final KS proof for ORHE rows.
    // - ciphertext_size_bytes counts encrypted inputs once per batch plus any per-comparison
    //   transient ciphertexts that the measured mode materializes and reports.
    // - metadata_size_bytes counts non-ciphertext online protocol data such as handles.
    // - total_online_comm_bytes counts only measured online communication for the compare pass.
    // - server_state_bytes / gate_state_bytes are persistent ORHE state snapshots after input
    //   registration for the measured construction; plain TFHE rows report zero.
    std::fprintf(
        f,
        "label,mode,batch_size,num_comparisons,"
        "exec_tfhe_us,verify_tfhe_us,prover_us,verifier_us,end_to_end_online_us,"
        "compare_tfhe_us,compare_prover_us,compare_verifier_us,"
        "exec_subtraction_us,exec_signbit_pbs_us,exec_internal_ks_us,exec_final_cmp_ks_us,"
        "verify_subtraction_us,verify_final_cmp_ks_us,"
        "accum_init_us,blind_rotate_us,extract_us,"
        "proof_size_bytes,ciphertext_size_bytes,metadata_size_bytes,total_online_comm_bytes,"
        "server_state_bytes,gate_state_bytes\n"
    );
}

static void print_bench_csv_row(FILE* f, const ThresholdBenchRow* row) {
    const ORHEMetrics* m = &row->metrics;
    std::fprintf(
        f,
        "%s,%s,%d,%d,"
        "%llu,%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu\n",
        row->label,
        row->mode,
        row->batch_size,
        row->num_comparisons,
        (unsigned long long) m->exec_tfhe_us,
        (unsigned long long) m->verify_tfhe_us,
        (unsigned long long) m->prover_us,
        (unsigned long long) m->verifier_us,
        (unsigned long long) m->end_to_end_online_us,
        (unsigned long long) m->compare_tfhe_us,
        (unsigned long long) m->compare_prover_us,
        (unsigned long long) m->compare_verifier_us,
        (unsigned long long) m->exec_subtraction_us,
        (unsigned long long) m->exec_signbit_pbs_us,
        (unsigned long long) m->exec_internal_ks_us,
        (unsigned long long) m->exec_final_cmp_ks_us,
        (unsigned long long) m->verify_subtraction_us,
        (unsigned long long) m->verify_final_cmp_ks_us,
        (unsigned long long) m->accum_init_us,
        (unsigned long long) m->blind_rotate_us,
        (unsigned long long) m->extract_us,
        (unsigned long long) m->proof_size_bytes,
        (unsigned long long) m->ciphertext_size_bytes,
        (unsigned long long) m->metadata_size_bytes,
        (unsigned long long) m->total_online_comm_bytes,
        (unsigned long long) m->server_state_bytes,
        (unsigned long long) m->gate_state_bytes
    );
}

static bool run_plain_tfhe_batch(
    const std::vector<ORHECiphertext*>& values,
    const std::vector<uint32_t>& plaintexts,
    const ORHECiphertext* threshold_ct,
    uint32_t threshold_plain,
    const ORHEKeySet* ks,
    ThresholdBenchRow* out_row
) {
    ORHEMetrics total;
    orhe_metrics_reset(&total);

    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);

    for (size_t i = 0; i < values.size(); ++i) {
        ORHEMetrics step;
        orhe_metrics_reset(&step);

        const int sigma = orhe_compare_plain_with_metrics(values[i], threshold_ct, c_sgn, u, ks, &step);
        const int expected = (plaintexts[i] < threshold_plain) ? 1 : 0;
        if (sigma != expected) {
            delete_gate_bootstrapping_ciphertext(c_sgn);
            delete_LweSample(u);
            return false;
        }

        orhe_metrics_add(&total, &step);
    }

    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);

    total.ciphertext_size_bytes += input_ciphertext_bytes(values, threshold_ct);
    total.server_state_bytes = 0;
    total.gate_state_bytes = 0;

    out_row->label = "threshold_filter_lt";
    out_row->mode = "plain_tfhe";
    out_row->batch_size = (int32_t) values.size();
    out_row->num_comparisons = (int32_t) values.size();
    out_row->metrics = total;
    return true;
}

static bool run_orhe_batch(
    const std::vector<uint64_t>& handles,
    uint64_t threshold_handle,
    const std::vector<ORHECiphertext*>& values,
    const std::vector<uint32_t>& plaintexts,
    const ORHECiphertext* threshold_ct,
    uint32_t threshold_plain,
    const ORHEHandleTable* H,
    const ORHEKeySet* ks,
    ThresholdBenchRow* out_row
) {
    ORHEMetrics total;
    orhe_metrics_reset(&total);

    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);

    for (size_t i = 0; i < handles.size(); ++i) {
        ORHEMetrics prove_metrics;
        ORHEMetrics verify_metrics;
        ORHEProof pi;
        init_empty_proof(&pi);
        orhe_metrics_reset(&prove_metrics);
        orhe_metrics_reset(&verify_metrics);

        const int prove_ok = orhe_compare_server_prove_with_metrics(
            handles[i],
            threshold_handle,
            H,
            c_sgn,
            u,
            &pi,
            ks,
            &prove_metrics
        );
        if (prove_ok != 1) {
            orhe_proof_clear(&pi);
            delete_gate_bootstrapping_ciphertext(c_sgn);
            delete_LweSample(u);
            return false;
        }

        const int sigma = orhe_gate_compare_verified_with_metrics(
            handles[i],
            threshold_handle,
            H,
            c_sgn,
            u,
            &pi,
            ks,
            &verify_metrics
        );
        const int expected = (plaintexts[i] < threshold_plain) ? 1 : 0;
        orhe_proof_clear(&pi);
        if (sigma != expected) {
            delete_gate_bootstrapping_ciphertext(c_sgn);
            delete_LweSample(u);
            return false;
        }

        orhe_metrics_add(&total, &prove_metrics);
        orhe_metrics_add(&total, &verify_metrics);
    }

    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);

    total.ciphertext_size_bytes += input_ciphertext_bytes(values, threshold_ct);
    total.server_state_bytes = orhe_handle_table_size_bytes(H);
    total.gate_state_bytes = orhe_gate_state_size_bytes(ks);

    out_row->label = "threshold_filter_lt";
    out_row->mode = "orhe";
    out_row->batch_size = (int32_t) values.size();
    out_row->num_comparisons = (int32_t) values.size();
    out_row->metrics = total;
    return true;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    _putenv_s("ORHE_ENABLE_INSECURE_DEBUG_APIS", "1");
#else
    setenv("ORHE_ENABLE_INSECURE_DEBUG_APIS", "1", 1);
#endif

    ThresholdBenchConfig cfg;
    if (!parse_args(argc, argv, &cfg)) {
        std::fprintf(stderr, "usage: %s [--batch-size N] [--batch-sizes a,b,c] [--csv PATH]\n", argv[0]);
        return 1;
    }

    FILE* out = stdout;
    if (!cfg.csv_path.empty()) {
        out = std::fopen(cfg.csv_path.c_str(), "w");
        if (!out) {
            std::fprintf(stderr, "failed to open csv output: %s\n", cfg.csv_path.c_str());
            return 1;
        }
    }

    ORHEParams params;
    params.bit_width = 8;
    params.domain_min = 0;
    params.domain_max = 127;

    ORHEKeySet* ks = orhe_new_keyset(110, &params);
    const uint32_t threshold_plain = 48;

    print_bench_csv_header(out);

    for (size_t batch_idx = 0; batch_idx < cfg.batch_sizes.size(); ++batch_idx) {
        const int32_t batch_size = cfg.batch_sizes[batch_idx];
        const std::vector<uint32_t> plaintexts = build_dataset(batch_size);

        std::vector<ORHECiphertext*> values;
        values.reserve((size_t) batch_size);

        ORHECiphertext* threshold_ct = orhe_new_ciphertext(params.bit_width, ks->tfhe_params);
        orhe_sym_encrypt_uint(threshold_ct, threshold_plain, ks);

        ORHEHandleTable H;
        orhe_init_table(&H);

        std::vector<uint64_t> handles;
        handles.reserve((size_t) batch_size);
        const uint64_t threshold_handle = 9000000ULL + (uint64_t) batch_size;

        bool ok = register_base_checked(&H, threshold_handle, threshold_ct, ks);
        for (int32_t i = 0; ok && i < batch_size; ++i) {
            ORHECiphertext* ct = orhe_new_ciphertext(params.bit_width, ks->tfhe_params);
            orhe_sym_encrypt_uint(ct, plaintexts[(size_t) i], ks);
            values.push_back(ct);
            const uint64_t handle = 100000ULL + (uint64_t) batch_size * 1000ULL + (uint64_t) i;
            handles.push_back(handle);
            ok = register_base_checked(&H, handle, ct, ks);
        }

        if (!ok) {
            std::fprintf(stderr, "base registration failed for batch size %d\n", batch_size);
            orhe_free_table(&H);
            delete_ciphertext_vector(&values);
            orhe_delete_ciphertext(threshold_ct);
            orhe_delete_keyset(ks);
            if (out != stdout) std::fclose(out);
            return 1;
        }

        ThresholdBenchRow plain_row;
        ThresholdBenchRow orhe_row;
        if (!run_plain_tfhe_batch(values, plaintexts, threshold_ct, threshold_plain, ks, &plain_row) ||
            !run_orhe_batch(handles, threshold_handle, values, plaintexts, threshold_ct, threshold_plain, &H, ks, &orhe_row)) {
            std::fprintf(stderr, "benchmark validation failed for batch size %d\n", batch_size);
            orhe_free_table(&H);
            delete_ciphertext_vector(&values);
            orhe_delete_ciphertext(threshold_ct);
            orhe_delete_keyset(ks);
            if (out != stdout) std::fclose(out);
            return 1;
        }

        print_bench_csv_row(out, &plain_row);
        print_bench_csv_row(out, &orhe_row);

        orhe_free_table(&H);
        delete_ciphertext_vector(&values);
        orhe_delete_ciphertext(threshold_ct);
    }

    orhe_delete_keyset(ks);
    if (out != stdout) std::fclose(out);
    return 0;
}
