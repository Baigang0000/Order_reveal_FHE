#ifndef ORHE_H
#define ORHE_H

#include <stdint.h>
#include "tfhe.h"
#include "tfhe_gate_bootstrapping_structures.h"
#include "lwekeyswitch.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ORHEBackendHandle ORHEBackendHandle;
typedef struct ORHEMetrics ORHEMetrics;

typedef enum {
    ORHE_PROOF_FAMILY_NONE = 0,
    ORHE_PROOF_FAMILY_PBS = 1,
    ORHE_PROOF_FAMILY_SIGNEXT = 2,
    ORHE_PROOF_FAMILY_KS = 3,
    ORHE_PROOF_FAMILY_SUB = 4
} ORHEProofFamily;

typedef struct {
    uint8_t bytes[32];
} ORHEAuthPublicKey;

typedef struct {
    uint8_t bytes[32];
} ORHEAuthSecretKey;

typedef struct {
    uint8_t bytes[32];
} ORHEAuthSignature;

typedef struct {
    int32_t family;
    int32_t bit_width;
    int32_t backend_mode;
    ORHEBackendHandle* backend;
} ORHEProofPP;

typedef struct {
    int32_t family;
    uint8_t* blob;
    uint64_t blob_len;
    uint8_t owns_backend_buffer;
} ORHEProof;

typedef struct {
    int32_t bit_width;
    int32_t domain_min;
    int32_t domain_max;
} ORHEParams;

typedef struct {
    uint8_t* ptr;
    uint64_t len;
} ORHEBytes;

typedef struct {
    uint8_t params_id[32];
    uint8_t lut_id[32];
    uint8_t bk_fft_id[32];
    uint8_t pbs_ks_id[32];
    uint8_t ctx_root[32];
} ORHETFHEContextId;

typedef struct {
    uint32_t version;
    ORHEBytes pbs_input_ser;
    ORHEBytes accum_init_tlwe_ser;
    uint8_t ctx_root[32];
} ORHESignExtB1AccumulatorInitCheckpoint;

typedef struct {
    uint32_t version;
    ORHEBytes pbs_input_ser;
    ORHEBytes accum_init_tlwe_ser;
    ORHEBytes blind_rot_accum_tlwe_ser;
    uint8_t ctx_root[32];
} ORHESignExtB2BlindRotateCheckpoint;

typedef struct {
    uint32_t version;
    ORHEBytes blind_rot_accum_tlwe_ser;
    ORHEBytes pre_ks_lwe_ser;
    uint8_t ctx_root[32];
} ORHESignExtB3ExtractCheckpoint;

typedef struct {
    uint32_t version;
    ORHEBytes pre_ks_lwe_ser;
    ORHEBytes c_sgn_ser;
    uint8_t pbs_ks_id[32];
    uint8_t ctx_root[32];
} ORHESignExtB4InternalKsCheckpoint;

typedef struct {
    uint32_t version;
    ORHEBytes d_ser;
    ORHEBytes pbs_input_ser;
    ORHEBytes c_sgn_ser;
    uint32_t relation_id;
    ORHETFHEContextId tfhe_ctx_id;
} ORHESignExtPublicStatement;

typedef struct {
    uint32_t version;
    ORHEBytes pbs_input_ser;
    ORHEBytes pre_ks_lwe_ser;
    ORHESignExtB1AccumulatorInitCheckpoint b1;
    ORHESignExtB2BlindRotateCheckpoint b2;
    ORHESignExtB3ExtractCheckpoint b3;
    ORHESignExtB4InternalKsCheckpoint b4;
} ORHESignExtWitness;

typedef enum {
    ORHE_BACKEND_MODE_REFERENCE = 0,
    ORHE_BACKEND_MODE_SIGNEXT_PARTIAL_SEMANTIC_B1_B3 = 1,
    ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC = 2,
    ORHE_BACKEND_MODE_SUB_PARTIAL_TRACE = 3
} ORHEBackendMode;

typedef struct {
    int32_t nbits;
    // Current ORHE values are represented as bit-sliced ciphertext vectors in
    // little-endian bit order. The compare path operates over this existing
    // ORHECiphertext layout directly.
    LweSample* bits;
    const TFheGateBootstrappingParameterSet* tfhe_params;
    const LweParams* lwe_params;
} ORHECiphertext;

typedef struct {
    uint64_t handle;
    ORHECiphertext* ct;
    uint8_t ct_digest[32];
    uint8_t is_base;
} ORHEHandleEntry;

typedef struct {
    ORHEHandleEntry* entries;
    int32_t size;
    int32_t cap;
} ORHEHandleTable;

typedef struct {
    const TFheGateBootstrappingParameterSet* tfhe_params;
    TFheGateBootstrappingSecretKeySet* data_sk;
    LweKey* cmp_sk;
    LweKeySwitchKey* data_to_cmp_ks;
    ORHEParams params;

    ORHEAuthPublicKey auth_pk;
    ORHEAuthSecretKey auth_sk;

    ORHEProofPP* pbs_pp;
    ORHEProofPP* reg_pbs_pp;
    ORHEProofPP* signext_pp;
    ORHEProofPP* sub_pp;
    ORHEProofPP* ks_pp;
} ORHEKeySet;

typedef enum {
    ORHE_TRACE_OP_INPUT = 0,
    ORHE_TRACE_OP_COPY = 1,
    ORHE_TRACE_OP_CONST = 2,
    ORHE_TRACE_OP_NOT = 3,
    ORHE_TRACE_OP_XOR = 4,
    ORHE_TRACE_OP_AND = 5,
    ORHE_TRACE_OP_OR = 6,
    ORHE_TRACE_OP_MUX = 7,
    ORHE_TRACE_OP_ADD = 8,
    ORHE_TRACE_OP_SUB = 9,
    ORHE_TRACE_OP_PBS = 10,
    ORHE_TRACE_OP_SHR = 11
} ORHETraceOpKind;

typedef enum {
    ORHE_PBS_RELATION_NONE = 0,
    ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE = 2,
    ORHE_PBS_RELATION_T3_BITWISE_NOT = 3,
    ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS = 4,
    ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB = 5
} ORHEPBSRelationKind;

typedef struct {
    ORHETraceOpKind kind;
    int32_t dst_wire;
    int32_t src0_wire;
    int32_t src1_wire;
    int32_t src2_wire;
    int32_t aux_value;
} ORHETraceOp;

typedef struct {
    ORHECiphertext* x_in;
    ORHECiphertext* y_out;
    ORHEProof proof;
} ORHEPBSCheckpoint;

typedef struct {
    ORHEProof proof;
} ORHESubCheckpoint;

typedef struct {
    ORHETraceOp* ops;
    int32_t nops;
    int32_t cap_ops;

    ORHEPBSCheckpoint* checkpoints;
    int32_t ncheckpoints;
    int32_t cap_checkpoints;

    ORHESubCheckpoint* sub_checkpoints;
    int32_t nsub_checkpoints;
    int32_t cap_sub_checkpoints;

    ORHECiphertext** wire_snapshots;
    int32_t nwire_snapshots;
    int32_t cap_wire_snapshots;

    int32_t final_wire;
    int32_t bit_width;
} ORHECircuitTrace;

// Key management
ORHEKeySet* orhe_new_keyset(int32_t minimum_lambda, const ORHEParams* params);
void orhe_delete_keyset(ORHEKeySet* ks);

// Auth for RegisterBase
void orhe_auth_keygen(ORHEAuthPublicKey* pk, ORHEAuthSecretKey* sk);
void orhe_auth_sign(
    ORHEAuthSignature* sig,
    uint64_t h,
    const ORHECiphertext* ct,
    const ORHEAuthSecretKey* sk
);
int32_t orhe_auth_verify(
    uint64_t h,
    const ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEAuthPublicKey* pk
);

// Proof backend API
void orhe_proof_clear(ORHEProof* proof);

ORHEProofPP* orhe_proof_setup(int32_t family, int32_t bit_width);
ORHEProofPP* orhe_proof_setup_pbs_semantic(int32_t bit_width, int32_t lwe_n);
ORHEProofPP* orhe_proof_setup_signext_semantic(int32_t bit_width);
ORHEProofPP* orhe_proof_setup_sub_partial(int32_t bit_width);
void orhe_proof_pp_delete(ORHEProofPP* pp);

void orhe_bytes_clear(ORHEBytes* bytes);
void orhe_signext_b4_clear(ORHESignExtB4InternalKsCheckpoint* ckpt);
void orhe_signext_public_statement_clear(ORHESignExtPublicStatement* stmt);
void orhe_signext_witness_clear(ORHESignExtWitness* wit);

int32_t orhe_signext_build_tfhe_ctx_id(
    ORHETFHEContextId* out,
    const ORHEKeySet* ks
);
int32_t orhe_signext_validate_tfhe_ctx_id(
    const ORHETFHEContextId* expected,
    const ORHEKeySet* ks
);
int32_t orhe_signext_build_public_statement(
    ORHESignExtPublicStatement* out,
    const ORHECiphertext* d,
    const LweSample* c_sgn,
    const ORHEKeySet* ks
);
int32_t orhe_signext_build_witness(
    ORHESignExtWitness* out,
    const ORHECiphertext* d,
    const LweSample* c_sgn,
    const ORHEKeySet* ks
);

void orhe_proof_prove_pbs(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out
);
int32_t orhe_proof_verify_pbs(
    const ORHEProofPP* pp,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof
);
void orhe_proof_prove_pbs_relation(
    ORHEProof* out,
    const ORHEProofPP* pp,
    int32_t relation,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEKeySet* ks
);
int32_t orhe_proof_verify_pbs_relation(
    const ORHEProofPP* pp,
    int32_t relation,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof,
    const ORHEKeySet* ks
);

void orhe_proof_prove_signext(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const TFheGateBootstrappingParameterSet* params
);
int32_t orhe_proof_verify_signext(
    const ORHEProofPP* pp,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const ORHEProof* proof,
    const TFheGateBootstrappingParameterSet* params
);

void orhe_proof_prove_signext_semantic(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit
);
int32_t orhe_proof_verify_signext_semantic(
    const ORHEProofPP* pp,
    const ORHESignExtPublicStatement* stmt,
    const ORHEProof* proof,
    const ORHEKeySet* ks
);

void orhe_proof_prove_sub_partial(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHEKeySet* ks
);
int32_t orhe_proof_verify_sub_partial(
    const ORHEProofPP* pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHEProof* proof,
    const ORHEKeySet* ks
);

void orhe_proof_prove_ks(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params
);
int32_t orhe_proof_verify_ks(
    const ORHEProofPP* pp,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* proof,
    const TFheGateBootstrappingParameterSet* params
);

// Ciphertext allocation
ORHECiphertext* orhe_new_ciphertext(
    int32_t nbits,
    const TFheGateBootstrappingParameterSet* params
);
void orhe_delete_ciphertext(ORHECiphertext* ct);

// Symmetric encrypt/decrypt
void orhe_sym_encrypt_uint(ORHECiphertext* out, uint32_t m, const ORHEKeySet* ks);
uint32_t orhe_sym_decrypt_uint(const ORHECiphertext* ct, const ORHEKeySet* ks);

// Handle table
void orhe_init_table(ORHEHandleTable* H);
void orhe_free_table(ORHEHandleTable* H);

int32_t orhe_register_base(
    ORHEHandleTable* H,
    uint64_t h,
    ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEKeySet* ks
);

const ORHEHandleEntry* orhe_lookup(const ORHEHandleTable* H, uint64_t h);

// Homomorphic bit-vector ops
void orhe_copy(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_not(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_xor(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_and(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_or(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_mux(
    ORHECiphertext* out,
    const LweSample* cond,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_add(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

// Compare currently uses this existing bit-sliced subtractor over
// ORHECiphertext inputs; this is not the single-TLWE subtraction refactor.
void orhe_sub(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_shr(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int32_t shift,
    const TFheGateBootstrappingCloudKeySet* bk
);

int32_t orhe_eval_allowed_pbs_relation(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int32_t relation,
    const ORHEKeySet* ks
);

void orhe_sign_bit(
    LweSample* out_sign,
    const ORHECiphertext* diff,
    const TFheGateBootstrappingCloudKeySet* bk
);

void orhe_switch_sign_to_cmp(
    LweSample* out_cmp,
    const LweSample* sign_bit_data_domain,
    const ORHEKeySet* ks
);

// Trace / RegisterDer support
ORHECircuitTrace* orhe_trace_new(int32_t bit_width);
void orhe_trace_delete(ORHECircuitTrace* tr);

int32_t orhe_trace_append_op(
    ORHECircuitTrace* tr,
    ORHETraceOp op
);

int32_t orhe_trace_append_pbs_checkpoint(
    ORHECircuitTrace* tr,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof
);
int32_t orhe_trace_append_sub_checkpoint(
    ORHECircuitTrace* tr,
    const ORHEProof* proof
);

int32_t orhe_trace_record_wire(
    ORHECircuitTrace* tr,
    int32_t wire,
    const ORHECiphertext* value
);

int32_t orhe_register_derived(
    ORHEHandleTable* H,
    uint64_t h_new,
    const uint64_t* src_handles,
    int32_t nsrc,
    ORHECiphertext* c_claimed,
    const ORHECircuitTrace* tr,
    const ORHEKeySet* ks
);

const char* orhe_register_derived_last_error(void);

// Compare oracle
// Current secure compare implementation:
// - bit-sliced ORHECiphertext subtraction (wrapped two's-complement bit-slice)
// - trace-backed compare proof for the subtraction/sign-bit pipeline:
//   the prover records the bit-sliced subtraction transcript and proves each
//   checkpoint gate, including the final sign-bit PBS, without relying on a
//   verifier-side TFHE rerun of the compare circuit
// - explicit final compare-domain key switch proven separately via the KS proof path;
//   gate verification checks that proof bundle and then decrypts u without
//   recomputing the key switch in TFHE
int32_t orhe_compare_server_prove(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    LweSample* c_sgn_out,
    LweSample* u_out,
    ORHEProof* pi_out,
    const ORHEKeySet* ks
);

int32_t orhe_gate_compare_verified(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi,
    const ORHEKeySet* ks
);

// Legacy debug-only compare. The secure evaluation flow must use
// `orhe_gate_compare_verified`.
int32_t orhe_gate_compare(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* claimed_cmp,
    const ORHEKeySet* ks
);

// metric-aware wrappers
int32_t orhe_register_base_with_metrics(
    ORHEHandleTable* H,
    uint64_t h,
    ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEKeySet* ks,
    ORHEMetrics* m
);

int32_t orhe_register_derived_with_metrics(
    ORHEHandleTable* H,
    uint64_t h_new,
    const uint64_t* src_handles,
    int32_t nsrc,
    ORHECiphertext* c_claimed,
    const ORHECircuitTrace* tr,
    const ORHEKeySet* ks,
    ORHEMetrics* m
);

int32_t orhe_compare_server_prove_with_metrics(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    LweSample* c_sgn_out,
    LweSample* u_out,
    ORHEProof* pi_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m
);

int32_t orhe_compare_plain_with_metrics(
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    LweSample* c_sgn_out,
    LweSample* u_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m
);

int32_t orhe_gate_compare_verified_with_metrics(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi,
    const ORHEKeySet* ks,
    ORHEMetrics* m
);

#ifdef __cplusplus
}
#endif

#endif
