#ifndef ORHE_PLONKY2_BACKEND_H
#define ORHE_PLONKY2_BACKEND_H

#include <stdint.h>
#include "orhe.h"

#ifdef __cplusplus
extern "C" {
#endif

void* orhe_backend_setup_bridge(int32_t family, int32_t bit_width);
void* orhe_backend_setup_pbs_semantic_bridge(int32_t bit_width, int32_t lwe_n);
void* orhe_backend_setup_signext_semantic_bridge(int32_t bit_width);
void orhe_backend_free_bridge(void* handle);

int32_t orhe_backend_prove_pbs_bridge(
    void* handle,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    uint8_t** out_ptr,
    uint64_t* out_len
);

int32_t orhe_backend_verify_pbs_bridge(
    void* handle,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);
int32_t orhe_backend_prove_pbs_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
);
int32_t orhe_backend_verify_pbs_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

int32_t orhe_backend_prove_signext_bridge(
    void* handle,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const uint8_t* trace_ptr,
    uint64_t trace_len,
    const uint8_t* witness_ptr,
    uint64_t witness_len,
    const TFheGateBootstrappingParameterSet* params,
    uint8_t** out_ptr,
    uint64_t* out_len
);

int32_t orhe_backend_verify_signext_bridge(
    void* handle,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const uint8_t* trace_ptr,
    uint64_t trace_len,
    const TFheGateBootstrappingParameterSet* params,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

int32_t orhe_backend_prove_signext_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
);

int32_t orhe_backend_verify_signext_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

int32_t orhe_backend_prove_ks_bridge(
    void* handle,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params,
    uint8_t** out_ptr,
    uint64_t* out_len
);

int32_t orhe_backend_verify_ks_bridge(
    void* handle,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

void orhe_backend_free_buffer_bridge(uint8_t* ptr, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif
