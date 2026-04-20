#include "orhe_metrics.h"

#include <chrono>
#include <inttypes.h>
#include <string.h>

void orhe_metrics_reset(ORHEMetrics* m) {
    memset(m, 0, sizeof(*m));
}

void orhe_metrics_add(ORHEMetrics* dst, const ORHEMetrics* src) {
    if (!dst || !src) return;

    dst->exec_tfhe_us += src->exec_tfhe_us;
    dst->verify_tfhe_us += src->verify_tfhe_us;
    dst->prover_us += src->prover_us;
    dst->verifier_us += src->verifier_us;
    dst->end_to_end_online_us += src->end_to_end_online_us;

    dst->register_base_us += src->register_base_us;
    dst->register_derived_tfhe_us += src->register_derived_tfhe_us;
    dst->register_derived_prover_us += src->register_derived_prover_us;
    dst->register_derived_verifier_us += src->register_derived_verifier_us;
    dst->compare_tfhe_us += src->compare_tfhe_us;
    dst->compare_prover_us += src->compare_prover_us;
    dst->compare_verifier_us += src->compare_verifier_us;
    dst->exec_subtraction_us += src->exec_subtraction_us;
    dst->exec_signbit_pbs_us += src->exec_signbit_pbs_us;
    dst->exec_internal_ks_us += src->exec_internal_ks_us;
    dst->exec_final_cmp_ks_us += src->exec_final_cmp_ks_us;
    dst->verify_subtraction_us += src->verify_subtraction_us;
    dst->verify_final_cmp_ks_us += src->verify_final_cmp_ks_us;
    dst->accum_init_us += src->accum_init_us;
    dst->blind_rotate_us += src->blind_rotate_us;
    dst->extract_us += src->extract_us;

    dst->proof_size_bytes += src->proof_size_bytes;
    dst->ciphertext_size_bytes += src->ciphertext_size_bytes;
    dst->metadata_size_bytes += src->metadata_size_bytes;
    dst->total_online_comm_bytes += src->total_online_comm_bytes;

    // Keep the latest persistent-state snapshot when aggregating per-run rows.
    dst->server_state_bytes = src->server_state_bytes;
    dst->gate_state_bytes = src->gate_state_bytes;
}

uint64_t orhe_now_us(void) {
    using namespace std::chrono;
    return (uint64_t) duration_cast<microseconds>(
        steady_clock::now().time_since_epoch()
    ).count();
}

void orhe_timer_start(ORHETimer* t) {
    t->start_us = orhe_now_us();
}

uint64_t orhe_timer_elapsed_us(const ORHETimer* t) {
    uint64_t now = orhe_now_us();
    return now - t->start_us;
}

uint64_t orhe_lwe_size_bytes(const LweSample* s, const LweParams* params) {
    (void) s;
    if (!params) return 0;

    uint64_t out = 0;
    out += (uint64_t) params->n * sizeof(Torus32);  // a vector
    out += sizeof(Torus32);                         // b
    out += sizeof(double);                          // variance
    return out;
}

uint64_t orhe_ciphertext_size_bytes(const ORHECiphertext* ct) {
    if (!ct || !ct->lwe_params) return 0;
    return (uint64_t) ct->nbits * orhe_lwe_size_bytes(&ct->bits[0], ct->lwe_params);
}

uint64_t orhe_proof_size_bytes(const ORHEProof* p) {
    if (!p) return 0;
    return p->blob_len;
}

uint64_t orhe_handle_entry_size_bytes(const ORHEHandleEntry* e) {
    if (!e) return 0;

    uint64_t out = 0;
    out += sizeof(uint64_t);              // handle
    out += 32;                            // digest
    out += sizeof(uint8_t);               // is_base
    out += orhe_ciphertext_size_bytes(e->ct);
    return out;
}

uint64_t orhe_handle_table_size_bytes(const ORHEHandleTable* H) {
    if (!H) return 0;

    uint64_t total = 0;
    for (int32_t i = 0; i < H->size; ++i) {
        total += orhe_handle_entry_size_bytes(&H->entries[i]);
    }
    return total;
}

uint64_t orhe_gate_state_size_bytes(const ORHEKeySet* ks) {
    if (!ks || !ks->tfhe_params) return 0;

    uint64_t total = 0;

    // comparison secret key
    if (ks->cmp_sk && ks->cmp_sk->params) {
        total += (uint64_t) ks->cmp_sk->params->n * sizeof(int32_t);
    }

    // approximate proof-system state as fixed metadata if opaque
    total += sizeof(ORHEProofPP) * 3;

    return total;
}

void orhe_metrics_print_csv_header(FILE* f) {
    fprintf(
        f,
        "label,"
        "exec_tfhe_us,verify_tfhe_us,prover_us,verifier_us,end_to_end_online_us,"
        "register_base_us,register_derived_tfhe_us,register_derived_prover_us,register_derived_verifier_us,"
        "compare_tfhe_us,compare_prover_us,compare_verifier_us,"
        "exec_subtraction_us,exec_signbit_pbs_us,exec_internal_ks_us,exec_final_cmp_ks_us,"
        "verify_subtraction_us,verify_final_cmp_ks_us,"
        "accum_init_us,blind_rotate_us,extract_us,"
        "proof_size_bytes,ciphertext_size_bytes,metadata_size_bytes,total_online_comm_bytes,"
        "server_state_bytes,gate_state_bytes\n"
    );
}

void orhe_metrics_print_csv_row(FILE* f, const char* label, const ORHEMetrics* m) {
    fprintf(
        f,
        "%s,"
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 "\n",
        label,
        m->exec_tfhe_us, m->verify_tfhe_us, m->prover_us, m->verifier_us, m->end_to_end_online_us,
        m->register_base_us, m->register_derived_tfhe_us, m->register_derived_prover_us, m->register_derived_verifier_us,
        m->compare_tfhe_us, m->compare_prover_us, m->compare_verifier_us,
        m->exec_subtraction_us, m->exec_signbit_pbs_us, m->exec_internal_ks_us, m->exec_final_cmp_ks_us,
        m->verify_subtraction_us, m->verify_final_cmp_ks_us,
        m->accum_init_us, m->blind_rotate_us, m->extract_us,
        m->proof_size_bytes, m->ciphertext_size_bytes, m->metadata_size_bytes, m->total_online_comm_bytes,
        m->server_state_bytes, m->gate_state_bytes
    );
}

void orhe_metrics_print_pretty(FILE* f, const char* label, const ORHEMetrics* m) {
    fprintf(f, "=== %s ===\n", label);
    fprintf(f, "exec_tfhe_us: %" PRIu64 "\n", m->exec_tfhe_us);
    fprintf(f, "verify_tfhe_us: %" PRIu64 "\n", m->verify_tfhe_us);
    fprintf(f, "prover_us: %" PRIu64 "\n", m->prover_us);
    fprintf(f, "verifier_us: %" PRIu64 "\n", m->verifier_us);
    fprintf(f, "end_to_end_online_us: %" PRIu64 "\n", m->end_to_end_online_us);
    fprintf(f, "register_base_us: %" PRIu64 "\n", m->register_base_us);
    fprintf(f, "register_derived_tfhe_us: %" PRIu64 "\n", m->register_derived_tfhe_us);
    fprintf(f, "register_derived_prover_us: %" PRIu64 "\n", m->register_derived_prover_us);
    fprintf(f, "register_derived_verifier_us: %" PRIu64 "\n", m->register_derived_verifier_us);
    fprintf(f, "compare_tfhe_us: %" PRIu64 "\n", m->compare_tfhe_us);
    fprintf(f, "compare_prover_us: %" PRIu64 "\n", m->compare_prover_us);
    fprintf(f, "compare_verifier_us: %" PRIu64 "\n", m->compare_verifier_us);
    fprintf(f, "exec_subtraction_us: %" PRIu64 "\n", m->exec_subtraction_us);
    fprintf(f, "exec_signbit_pbs_us: %" PRIu64 "\n", m->exec_signbit_pbs_us);
    fprintf(f, "exec_internal_ks_us: %" PRIu64 "\n", m->exec_internal_ks_us);
    fprintf(f, "exec_final_cmp_ks_us: %" PRIu64 "\n", m->exec_final_cmp_ks_us);
    fprintf(f, "verify_subtraction_us: %" PRIu64 "\n", m->verify_subtraction_us);
    fprintf(f, "verify_final_cmp_ks_us: %" PRIu64 "\n", m->verify_final_cmp_ks_us);
    fprintf(f, "accum_init_us: %" PRIu64 "\n", m->accum_init_us);
    fprintf(f, "blind_rotate_us: %" PRIu64 "\n", m->blind_rotate_us);
    fprintf(f, "extract_us: %" PRIu64 "\n", m->extract_us);
    fprintf(f, "proof_size_bytes: %" PRIu64 "\n", m->proof_size_bytes);
    fprintf(f, "ciphertext_size_bytes: %" PRIu64 "\n", m->ciphertext_size_bytes);
    fprintf(f, "metadata_size_bytes: %" PRIu64 "\n", m->metadata_size_bytes);
    fprintf(f, "total_online_comm_bytes: %" PRIu64 "\n", m->total_online_comm_bytes);
    fprintf(f, "server_state_bytes: %" PRIu64 "\n", m->server_state_bytes);
    fprintf(f, "gate_state_bytes: %" PRIu64 "\n", m->gate_state_bytes);
}
