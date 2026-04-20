#ifndef ORHE_METRICS_H
#define ORHE_METRICS_H

#include <stdint.h>
#include <stdio.h>
#include "orhe.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ORHEMetrics {
    // Runtime metrics (microseconds)
    uint64_t exec_tfhe_us;              // compare-execution TFHE only
    uint64_t verify_tfhe_us;            // verifier-side TFHE recomputation only
    uint64_t prover_us;                 // ORHE proof generation time
    uint64_t verifier_us;               // proof-checking time only
    uint64_t end_to_end_online_us;      // whole client-visible operation

    // More granular decomposition
    uint64_t register_base_us;
    uint64_t register_derived_tfhe_us;
    uint64_t register_derived_prover_us;
    uint64_t register_derived_verifier_us;
    uint64_t compare_tfhe_us;           // exec_tfhe_us + verify_tfhe_us for compare rows
    uint64_t compare_prover_us;
    uint64_t compare_verifier_us;
    uint64_t exec_subtraction_us;
    uint64_t exec_signbit_pbs_us;
    uint64_t exec_internal_ks_us;
    uint64_t exec_final_cmp_ks_us;
    uint64_t verify_subtraction_us;
    uint64_t verify_final_cmp_ks_us;
    uint64_t accum_init_us;             // execution-side sign-bit PBS accumulator init
    uint64_t blind_rotate_us;           // execution-side sign-bit PBS blind rotation
    uint64_t extract_us;                // execution-side sign-bit PBS extraction

    // Communication / storage
    uint64_t proof_size_bytes;
    uint64_t ciphertext_size_bytes;
    uint64_t metadata_size_bytes;
    uint64_t total_online_comm_bytes;
    uint64_t server_state_bytes;
    uint64_t gate_state_bytes;
} ORHEMetrics;

typedef struct ORHETimer {
    uint64_t start_us;
} ORHETimer;

void orhe_metrics_reset(ORHEMetrics* m);
void orhe_metrics_add(ORHEMetrics* dst, const ORHEMetrics* src);

// timer helpers
uint64_t orhe_now_us(void);
void orhe_timer_start(ORHETimer* t);
uint64_t orhe_timer_elapsed_us(const ORHETimer* t);

// size helpers
uint64_t orhe_ciphertext_size_bytes(const ORHECiphertext* ct);
uint64_t orhe_lwe_size_bytes(const LweSample* s, const LweParams* params);
uint64_t orhe_proof_size_bytes(const ORHEProof* p);
uint64_t orhe_handle_entry_size_bytes(const ORHEHandleEntry* e);
uint64_t orhe_handle_table_size_bytes(const ORHEHandleTable* H);
uint64_t orhe_gate_state_size_bytes(const ORHEKeySet* ks);

// CSV helpers
void orhe_metrics_print_csv_header(FILE* f);
void orhe_metrics_print_csv_row(FILE* f, const char* label, const ORHEMetrics* m);

// Optional human-readable print
void orhe_metrics_print_pretty(FILE* f, const char* label, const ORHEMetrics* m);

#ifdef __cplusplus
}
#endif

#endif
