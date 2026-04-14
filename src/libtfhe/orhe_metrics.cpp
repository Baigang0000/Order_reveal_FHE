#include "orhe_metrics.h"

#include <chrono>
#include <inttypes.h>
#include <string.h>

void orhe_metrics_reset(ORHEMetrics* m) {
    memset(m, 0, sizeof(*m));
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
        "tfhe_eval_us,prover_us,verifier_us,end_to_end_online_us,"
        "register_base_us,register_derived_tfhe_us,register_derived_prover_us,register_derived_verifier_us,"
        "compare_tfhe_us,compare_prover_us,compare_verifier_us,"
        "proof_size_bytes,ciphertext_size_bytes,metadata_size_bytes,total_online_comm_bytes,"
        "server_state_bytes,gate_state_bytes\n"
    );
}

void orhe_metrics_print_csv_row(FILE* f, const char* label, const ORHEMetrics* m) {
    fprintf(
        f,
        "%s,"
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
        "%" PRIu64 ",%" PRIu64 "\n",
        label,
        m->tfhe_eval_us, m->prover_us, m->verifier_us, m->end_to_end_online_us,
        m->register_base_us, m->register_derived_tfhe_us, m->register_derived_prover_us, m->register_derived_verifier_us,
        m->compare_tfhe_us, m->compare_prover_us, m->compare_verifier_us,
        m->proof_size_bytes, m->ciphertext_size_bytes, m->metadata_size_bytes, m->total_online_comm_bytes,
        m->server_state_bytes, m->gate_state_bytes
    );
}

void orhe_metrics_print_pretty(FILE* f, const char* label, const ORHEMetrics* m) {
    fprintf(f, "=== %s ===\n", label);
    fprintf(f, "tfhe_eval_us: %" PRIu64 "\n", m->tfhe_eval_us);
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
    fprintf(f, "proof_size_bytes: %" PRIu64 "\n", m->proof_size_bytes);
    fprintf(f, "ciphertext_size_bytes: %" PRIu64 "\n", m->ciphertext_size_bytes);
    fprintf(f, "metadata_size_bytes: %" PRIu64 "\n", m->metadata_size_bytes);
    fprintf(f, "total_online_comm_bytes: %" PRIu64 "\n", m->total_online_comm_bytes);
    fprintf(f, "server_state_bytes: %" PRIu64 "\n", m->server_state_bytes);
    fprintf(f, "gate_state_bytes: %" PRIu64 "\n", m->gate_state_bytes);
}
