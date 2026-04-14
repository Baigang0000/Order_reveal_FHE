#include "orhe.h"
#include "orhe_plonky2_backend.h"
#include "orhe_metrics.h"

#include <cstdlib>
#include <cstring>
#include <stdexcept>

static void ensure_same_width(const ORHECiphertext* a, const ORHECiphertext* b) {
    if (a->nbits != b->nbits) {
        throw std::runtime_error("ORHE ciphertext width mismatch");
    }
}

static void ensure_capacity(ORHEHandleTable* H) {
    if (H->size < H->cap) return;

    int32_t newcap = (H->cap == 0) ? 8 : (2 * H->cap);
    ORHEHandleEntry* fresh = (ORHEHandleEntry*) std::malloc(sizeof(ORHEHandleEntry) * newcap);
    for (int32_t i = 0; i < H->size; ++i) fresh[i] = H->entries[i];
    std::free(H->entries);
    H->entries = fresh;
    H->cap = newcap;
}

static int32_t handle_index(const ORHEHandleTable* H, uint64_t h) {
    for (int32_t i = 0; i < H->size; ++i) {
        if (H->entries[i].handle == h) return i;
    }
    return -1;
}

static ORHECiphertext* orhe_clone_ciphertext(const ORHECiphertext* in) {
    ORHECiphertext* out = (ORHECiphertext*) std::malloc(sizeof(ORHECiphertext));
    out->nbits = in->nbits;
    out->tfhe_params = in->tfhe_params;
    out->lwe_params = in->lwe_params;
    out->bits = new_gate_bootstrapping_ciphertext_array(in->nbits, in->tfhe_params);
    for (int32_t i = 0; i < in->nbits; ++i) {
        lweCopy(&out->bits[i], &in->bits[i], in->lwe_params);
    }
    return out;
}

static void orhe_digest_bytes(uint8_t out[32], const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*) data;
    for (int i = 0; i < 32; ++i) out[i] = (uint8_t) (0xA5 ^ i);

    for (size_t i = 0; i < len; ++i) {
        out[i % 32] ^= (uint8_t) (p[i] + (uint8_t) i);
        out[(i * 7) % 32] = (uint8_t) (out[(i * 7) % 32] + p[i] + 13);
    }
}

static void orhe_digest_ciphertext(uint8_t out[32], const ORHECiphertext* ct) {
    uint8_t acc[32];
    for (int i = 0; i < 32; ++i) acc[i] = (uint8_t) (0x5C + i);

    orhe_digest_bytes(acc, &ct->nbits, sizeof(ct->nbits));
    int32_t n = ct->lwe_params->n;
    orhe_digest_bytes(acc, &n, sizeof(n));

    for (int32_t i = 0; i < ct->nbits; ++i) {
        const LweSample* s = &ct->bits[i];
        orhe_digest_bytes(acc, &s->a[0], sizeof(Torus32) * n);
        orhe_digest_bytes(acc, &s->b, sizeof(Torus32));
        orhe_digest_bytes(acc, &s->current_variance, sizeof(double));
    }

    std::memcpy(out, acc, 32);
}

static int32_t orhe_ct_equal(const ORHECiphertext* a, const ORHECiphertext* b) {
    if (!a || !b) return 0;
    if (a->nbits != b->nbits) return 0;
    if (a->lwe_params->n != b->lwe_params->n) return 0;

    for (int32_t i = 0; i < a->nbits; ++i) {
        const LweSample* x = &a->bits[i];
        const LweSample* y = &b->bits[i];
        if (x->b != y->b) return 0;
        if (x->current_variance != y->current_variance) return 0;
        for (int32_t j = 0; j < a->lwe_params->n; ++j) {
            if (x->a[j] != y->a[j]) return 0;
        }
    }
    return 1;
}

static void full_adder(
    LweSample* sum,
    LweSample* cout,
    const LweSample* x,
    const LweSample* y,
    const LweSample* cin,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    const TFheGateBootstrappingParameterSet* params = bk->params;

    LweSample* t1 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t2 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t3 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t4 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t5 = new_gate_bootstrapping_ciphertext(params);

    bootsXOR(t1, x, y, bk);
    bootsXOR(sum, t1, cin, bk);

    bootsAND(t2, x, y, bk);
    bootsAND(t3, x, cin, bk);
    bootsAND(t4, y, cin, bk);
    bootsOR(t5, t2, t3, bk);
    bootsOR(cout, t5, t4, bk);

    delete_gate_bootstrapping_ciphertext(t1);
    delete_gate_bootstrapping_ciphertext(t2);
    delete_gate_bootstrapping_ciphertext(t3);
    delete_gate_bootstrapping_ciphertext(t4);
    delete_gate_bootstrapping_ciphertext(t5);
}

static int32_t max_wire_index(const ORHECircuitTrace* tr) {
    int32_t mx = -1;
    for (int32_t i = 0; i < tr->nops; ++i) {
        const ORHETraceOp* op = &tr->ops[i];
        if (op->dst_wire > mx) mx = op->dst_wire;
        if (op->src0_wire > mx) mx = op->src0_wire;
        if (op->src1_wire > mx) mx = op->src1_wire;
        if (op->src2_wire > mx) mx = op->src2_wire;
    }
    if (tr->final_wire > mx) mx = tr->final_wire;
    return mx;
}

// --------------------------------------------------
// Proof backend wiring
// --------------------------------------------------

void orhe_proof_clear(ORHEProof* proof) {
    if (!proof) return;
    if (proof->blob) {
        if (proof->owns_backend_buffer) {
            orhe_backend_free_buffer_bridge(proof->blob, proof->blob_len);
        } else {
            std::free(proof->blob);
        }
    }
    proof->family = ORHE_PROOF_FAMILY_NONE;
    proof->blob = NULL;
    proof->blob_len = 0;
    proof->owns_backend_buffer = 0;
}

static void orhe_proof_copy(ORHEProof* dst, const ORHEProof* src) {
    dst->family = src->family;
    dst->blob = NULL;
    dst->blob_len = src->blob_len;
    dst->owns_backend_buffer = 0;

    if (!src->blob || src->blob_len == 0) {
        dst->blob_len = 0;
        return;
    }

    dst->blob = (uint8_t*) std::malloc((size_t) src->blob_len);
    std::memcpy(dst->blob, src->blob, (size_t) src->blob_len);
}

ORHEProofPP* orhe_proof_setup(int32_t family, int32_t bit_width) {
    ORHEProofPP* pp = (ORHEProofPP*) std::malloc(sizeof(ORHEProofPP));
    pp->family = family;
    pp->bit_width = bit_width;
    pp->backend = (ORHEBackendHandle*) orhe_backend_setup_bridge(family, bit_width);
    return pp;
}

void orhe_proof_pp_delete(ORHEProofPP* pp) {
    if (!pp) return;
    if (pp->backend) {
        orhe_backend_free_bridge((void*) pp->backend);
        pp->backend = NULL;
    }
    std::free(pp);
}

void orhe_proof_prove_pbs(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out
) {
    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (orhe_backend_prove_pbs_bridge(
            (void*) pp->backend,
            x_in,
            y_out,
            &out->blob,
            &out->blob_len)) {
        out->family = ORHE_PROOF_FAMILY_PBS;
        out->owns_backend_buffer = 1;
    }
}

int32_t orhe_proof_verify_pbs(
    const ORHEProofPP* pp,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof
) {
    if (!pp || !proof || proof->family != ORHE_PROOF_FAMILY_PBS) return 0;
    return orhe_backend_verify_pbs_bridge(
        (void*) pp->backend,
        x_in,
        y_out,
        proof->blob,
        proof->blob_len
    );
}

void orhe_proof_prove_signext(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const TFheGateBootstrappingParameterSet* params
) {
    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (orhe_backend_prove_signext_bridge(
            (void*) pp->backend,
            diff,
            c_sgn,
            params,
            &out->blob,
            &out->blob_len)) {
        out->family = ORHE_PROOF_FAMILY_SIGNEXT;
        out->owns_backend_buffer = 1;
    }
}

int32_t orhe_proof_verify_signext(
    const ORHEProofPP* pp,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const ORHEProof* proof,
    const TFheGateBootstrappingParameterSet* params
) {
    if (!pp || !proof || proof->family != ORHE_PROOF_FAMILY_SIGNEXT) return 0;
    return orhe_backend_verify_signext_bridge(
        (void*) pp->backend,
        diff,
        c_sgn,
        params,
        proof->blob,
        proof->blob_len
    );
}

void orhe_proof_prove_ks(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params
) {
    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (orhe_backend_prove_ks_bridge(
            (void*) pp->backend,
            c_sgn,
            u,
            params,
            &out->blob,
            &out->blob_len)) {
        out->family = ORHE_PROOF_FAMILY_KS;
        out->owns_backend_buffer = 1;
    }
}

int32_t orhe_proof_verify_ks(
    const ORHEProofPP* pp,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* proof,
    const TFheGateBootstrappingParameterSet* params
) {
    if (!pp || !proof || proof->family != ORHE_PROOF_FAMILY_KS) return 0;
    return orhe_backend_verify_ks_bridge(
        (void*) pp->backend,
        c_sgn,
        u,
        params,
        proof->blob,
        proof->blob_len
    );
}

// --------------------------------------------------
// Auth
// --------------------------------------------------

void orhe_auth_keygen(ORHEAuthPublicKey* pk, ORHEAuthSecretKey* sk) {
    for (int i = 0; i < 32; ++i) {
        uint8_t b = (uint8_t) (std::rand() & 0xff);
        pk->bytes[i] = b;
        sk->bytes[i] = b;
    }
}

void orhe_auth_sign(
    ORHEAuthSignature* sig,
    uint64_t h,
    const ORHECiphertext* ct,
    const ORHEAuthSecretKey* sk
) {
    uint8_t dct[32];
    uint8_t buf[8 + 32 + 32];

    orhe_digest_ciphertext(dct, ct);
    std::memcpy(buf, &h, 8);
    std::memcpy(buf + 8, dct, 32);
    std::memcpy(buf + 40, sk->bytes, 32);

    orhe_digest_bytes(sig->bytes, buf, sizeof(buf));
}

int32_t orhe_auth_verify(
    uint64_t h,
    const ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEAuthPublicKey* pk
) {
    ORHEAuthSignature expect;
    ORHEAuthSecretKey mirror;
    std::memcpy(mirror.bytes, pk->bytes, 32);
    orhe_auth_sign(&expect, h, ct, &mirror);
    return std::memcmp(sig->bytes, expect.bytes, 32) == 0;
}

// --------------------------------------------------
// Key management
// --------------------------------------------------

ORHEKeySet* orhe_new_keyset(int32_t minimum_lambda, const ORHEParams* params) {
    ORHEKeySet* out = (ORHEKeySet*) std::malloc(sizeof(ORHEKeySet));
    std::memset(out, 0, sizeof(*out));

    TFheGateBootstrappingParameterSet* p =
        new_default_gate_bootstrapping_parameters(minimum_lambda);

    TFheGateBootstrappingSecretKeySet* data_sk =
        new_random_gate_bootstrapping_secret_keyset(p);

    LweKey* cmp_sk = new_LweKey(p->in_out_params);
    lweKeyGen(cmp_sk);

    LweKeySwitchKey* ks_sw =
        new_LweKeySwitchKey(p->in_out_params->n, p->ks_t, p->ks_basebit, p->in_out_params);

    lweCreateKeySwitchKey(ks_sw, data_sk->lwe_key, cmp_sk);

    out->tfhe_params = p;
    out->data_sk = data_sk;
    out->cmp_sk = cmp_sk;
    out->data_to_cmp_ks = ks_sw;
    out->params = *params;

    orhe_auth_keygen(&out->auth_pk, &out->auth_sk);

    out->pbs_pp = orhe_proof_setup(ORHE_PROOF_FAMILY_PBS, params->bit_width);
    out->signext_pp = orhe_proof_setup(ORHE_PROOF_FAMILY_SIGNEXT, params->bit_width);
    out->ks_pp = orhe_proof_setup(ORHE_PROOF_FAMILY_KS, params->bit_width);

    return out;
}

void orhe_delete_keyset(ORHEKeySet* ks) {
    if (!ks) return;

    orhe_proof_pp_delete(ks->pbs_pp);
    orhe_proof_pp_delete(ks->signext_pp);
    orhe_proof_pp_delete(ks->ks_pp);

    delete_LweKeySwitchKey(ks->data_to_cmp_ks);
    delete_LweKey(ks->cmp_sk);
    delete_gate_bootstrapping_secret_keyset(ks->data_sk);
    delete_gate_bootstrapping_parameters((TFheGateBootstrappingParameterSet*) ks->tfhe_params);

    std::free(ks);
}

// --------------------------------------------------
// Ciphertext allocation
// --------------------------------------------------

ORHECiphertext* orhe_new_ciphertext(
    int32_t nbits,
    const TFheGateBootstrappingParameterSet* params
) {
    ORHECiphertext* out = (ORHECiphertext*) std::malloc(sizeof(ORHECiphertext));
    out->nbits = nbits;
    out->bits = new_gate_bootstrapping_ciphertext_array(nbits, params);
    out->tfhe_params = params;
    out->lwe_params = params->in_out_params;
    return out;
}

void orhe_delete_ciphertext(ORHECiphertext* ct) {
    if (!ct) return;
    delete_gate_bootstrapping_ciphertext_array(ct->nbits, ct->bits);
    std::free(ct);
}

// --------------------------------------------------
// Encrypt / decrypt
// --------------------------------------------------

void orhe_sym_encrypt_uint(ORHECiphertext* out, uint32_t m, const ORHEKeySet* ks) {
    for (int32_t i = 0; i < out->nbits; ++i) {
        int bit = (m >> i) & 1u;
        bootsSymEncrypt(&out->bits[i], bit, ks->data_sk);
    }
}

uint32_t orhe_sym_decrypt_uint(const ORHECiphertext* ct, const ORHEKeySet* ks) {
    uint32_t out = 0;
    for (int32_t i = 0; i < ct->nbits && i < 32; ++i) {
        int bit = bootsSymDecrypt(&ct->bits[i], ks->data_sk);
        out |= ((uint32_t) bit << i);
    }
    return out;
}

// --------------------------------------------------
// Handle table
// --------------------------------------------------

void orhe_init_table(ORHEHandleTable* H) {
    H->entries = NULL;
    H->size = 0;
    H->cap = 0;
}

void orhe_free_table(ORHEHandleTable* H) {
    if (!H) return;
    std::free(H->entries);
    H->entries = NULL;
    H->size = 0;
    H->cap = 0;
}

int32_t orhe_register_base(
    ORHEHandleTable* H,
    uint64_t h,
    ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEKeySet* ks
) {
    if (handle_index(H, h) >= 0) return 0;
    if (!orhe_auth_verify(h, ct, sig, &ks->auth_pk)) return 0;

    ensure_capacity(H);
    H->entries[H->size].handle = h;
    H->entries[H->size].ct = ct;
    orhe_digest_ciphertext(H->entries[H->size].ct_digest, ct);
    H->entries[H->size].is_base = 1;
    H->size += 1;
    return 1;
}

const ORHEHandleEntry* orhe_lookup(const ORHEHandleTable* H, uint64_t h) {
    int32_t idx = handle_index(H, h);
    if (idx < 0) return NULL;
    return &H->entries[idx];
}

// --------------------------------------------------
// Homomorphic operations
// --------------------------------------------------

void orhe_copy(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    if (out->nbits != in->nbits) {
        throw std::runtime_error("orhe_copy width mismatch");
    }
    for (int32_t i = 0; i < in->nbits; ++i) {
        bootsCOPY(&out->bits[i], &in->bits[i], bk);
    }
}

void orhe_not(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    if (out->nbits != in->nbits) {
        throw std::runtime_error("orhe_not width mismatch");
    }
    for (int32_t i = 0; i < in->nbits; ++i) {
        bootsNOT(&out->bits[i], &in->bits[i], bk);
    }
}

void orhe_xor(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_xor width mismatch");
    }
    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsXOR(&out->bits[i], &a->bits[i], &b->bits[i], bk);
    }
}

void orhe_and(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_and width mismatch");
    }
    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsAND(&out->bits[i], &a->bits[i], &b->bits[i], bk);
    }
}

void orhe_or(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_or width mismatch");
    }
    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsOR(&out->bits[i], &a->bits[i], &b->bits[i], bk);
    }
}

void orhe_mux(
    ORHECiphertext* out,
    const LweSample* cond,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_mux width mismatch");
    }
    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsMUX(&out->bits[i], cond, &a->bits[i], &b->bits[i], bk);
    }
}

void orhe_add(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_add width mismatch");
    }

    const TFheGateBootstrappingParameterSet* params = bk->params;
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* next_carry = new_gate_bootstrapping_ciphertext(params);

    bootsCONSTANT(carry, 0, bk);

    for (int32_t i = 0; i < a->nbits; ++i) {
        full_adder(&out->bits[i], next_carry, &a->bits[i], &b->bits[i], carry, bk);
        bootsCOPY(carry, next_carry, bk);
    }

    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(next_carry);
}

void orhe_sub(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_sub width mismatch");
    }

    const TFheGateBootstrappingParameterSet* params = bk->params;
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* b_not = new_gate_bootstrapping_ciphertext(params);
    LweSample* next_carry = new_gate_bootstrapping_ciphertext(params);

    bootsCONSTANT(carry, 1, bk);

    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsNOT(b_not, &b->bits[i], bk);
        full_adder(&out->bits[i], next_carry, &a->bits[i], b_not, carry, bk);
        bootsCOPY(carry, next_carry, bk);
    }

    delete_gate_bootstrapping_ciphertext(carry);
    delete_gate_bootstrapping_ciphertext(b_not);
    delete_gate_bootstrapping_ciphertext(next_carry);
}

void orhe_sign_bit(
    LweSample* out_sign,
    const ORHECiphertext* diff,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    bootsCOPY(out_sign, &diff->bits[diff->nbits - 1], bk);
}

void orhe_switch_sign_to_cmp(
    LweSample* out_cmp,
    const LweSample* sign_bit_data_domain,
    const ORHEKeySet* ks
) {
    lweKeySwitch(out_cmp, ks->data_to_cmp_ks, sign_bit_data_domain);
}

// --------------------------------------------------
// Trace helpers
// --------------------------------------------------

ORHECircuitTrace* orhe_trace_new(int32_t bit_width) {
    ORHECircuitTrace* tr = (ORHECircuitTrace*) std::malloc(sizeof(ORHECircuitTrace));
    tr->ops = NULL;
    tr->nops = 0;
    tr->cap_ops = 0;
    tr->checkpoints = NULL;
    tr->ncheckpoints = 0;
    tr->cap_checkpoints = 0;
    tr->final_wire = -1;
    tr->bit_width = bit_width;
    return tr;
}

void orhe_trace_delete(ORHECircuitTrace* tr) {
    if (!tr) return;

    for (int32_t i = 0; i < tr->ncheckpoints; ++i) {
        orhe_delete_ciphertext(tr->checkpoints[i].x_in);
        orhe_delete_ciphertext(tr->checkpoints[i].y_out);
        orhe_proof_clear(&tr->checkpoints[i].proof);
    }

    std::free(tr->ops);
    std::free(tr->checkpoints);
    std::free(tr);
}

static void trace_ensure_ops(ORHECircuitTrace* tr) {
    if (tr->nops < tr->cap_ops) return;
    int32_t newcap = (tr->cap_ops == 0) ? 8 : (2 * tr->cap_ops);
    ORHETraceOp* fresh = (ORHETraceOp*) std::malloc(sizeof(ORHETraceOp) * newcap);
    for (int32_t i = 0; i < tr->nops; ++i) fresh[i] = tr->ops[i];
    std::free(tr->ops);
    tr->ops = fresh;
    tr->cap_ops = newcap;
}

static void trace_ensure_checkpoints(ORHECircuitTrace* tr) {
    if (tr->ncheckpoints < tr->cap_checkpoints) return;
    int32_t newcap = (tr->cap_checkpoints == 0) ? 4 : (2 * tr->cap_checkpoints);
    ORHEPBSCheckpoint* fresh = (ORHEPBSCheckpoint*) std::malloc(sizeof(ORHEPBSCheckpoint) * newcap);
    for (int32_t i = 0; i < tr->ncheckpoints; ++i) fresh[i] = tr->checkpoints[i];
    std::free(tr->checkpoints);
    tr->checkpoints = fresh;
    tr->cap_checkpoints = newcap;
}

int32_t orhe_trace_append_op(ORHECircuitTrace* tr, ORHETraceOp op) {
    trace_ensure_ops(tr);
    tr->ops[tr->nops++] = op;
    return 1;
}

int32_t orhe_trace_append_pbs_checkpoint(
    ORHECircuitTrace* tr,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof
) {
    trace_ensure_checkpoints(tr);
    tr->checkpoints[tr->ncheckpoints].x_in = orhe_clone_ciphertext(x_in);
    tr->checkpoints[tr->ncheckpoints].y_out = orhe_clone_ciphertext(y_out);
    orhe_proof_copy(&tr->checkpoints[tr->ncheckpoints].proof, proof);
    tr->ncheckpoints += 1;
    return 1;
}

// --------------------------------------------------
// RegisterDer verifier
// --------------------------------------------------

int32_t orhe_register_derived(
    ORHEHandleTable* H,
    uint64_t h_new,
    const uint64_t* src_handles,
    int32_t nsrc,
    ORHECiphertext* c_claimed,
    const ORHECircuitTrace* tr,
    const ORHEKeySet* ks
) {
    if (orhe_lookup(H, h_new) != NULL) return 0;
    if (!tr) return 0;

    int32_t nwires = max_wire_index(tr) + 1;
    if (nwires <= 0) return 0;

    ORHECiphertext** wires = (ORHECiphertext**) std::malloc(sizeof(ORHECiphertext*) * nwires);
    for (int32_t i = 0; i < nwires; ++i) wires[i] = NULL;

    for (int32_t i = 0; i < nsrc; ++i) {
        const ORHEHandleEntry* e = orhe_lookup(H, src_handles[i]);
        if (!e) {
            std::free(wires);
            return 0;
        }
        wires[i] = orhe_clone_ciphertext(e->ct);
    }

    int32_t checkpoint_cursor = 0;

    for (int32_t i = 0; i < tr->nops; ++i) {
        const ORHETraceOp* op = &tr->ops[i];

        switch (op->kind) {
            case ORHE_TRACE_OP_INPUT:
                break;

            case ORHE_TRACE_OP_COPY:
                if (!wires[op->src0_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_copy(wires[op->dst_wire], wires[op->src0_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_CONST:
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_sym_encrypt_uint(wires[op->dst_wire], (uint32_t) op->aux_value, ks);
                break;

            case ORHE_TRACE_OP_NOT:
                if (!wires[op->src0_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_not(wires[op->dst_wire], wires[op->src0_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_XOR:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_xor(wires[op->dst_wire], wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_AND:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_and(wires[op->dst_wire], wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_OR:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_or(wires[op->dst_wire], wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_MUX:
                if (!wires[op->src0_wire] || !wires[op->src1_wire] || !wires[op->src2_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_mux(
                    wires[op->dst_wire],
                    &wires[op->src0_wire]->bits[0],
                    wires[op->src1_wire],
                    wires[op->src2_wire],
                    &ks->data_sk->cloud
                );
                break;

            case ORHE_TRACE_OP_ADD:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_add(wires[op->dst_wire], wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_SUB:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                wires[op->dst_wire] = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                orhe_sub(wires[op->dst_wire], wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                break;

            case ORHE_TRACE_OP_PBS: {
                if (checkpoint_cursor >= tr->ncheckpoints) goto fail;
                if (!wires[op->src0_wire]) goto fail;

                const ORHEPBSCheckpoint* cp = &tr->checkpoints[checkpoint_cursor++];

                if (!orhe_ct_equal(wires[op->src0_wire], cp->x_in)) goto fail;
                if (!orhe_proof_verify_pbs(ks->pbs_pp, cp->x_in, cp->y_out, &cp->proof)) goto fail;

                wires[op->dst_wire] = orhe_clone_ciphertext(cp->y_out);
                break;
            }

            default:
                goto fail;
        }
    }

    if (tr->final_wire < 0 || tr->final_wire >= nwires) goto fail;
    if (!wires[tr->final_wire]) goto fail;
    if (!orhe_ct_equal(wires[tr->final_wire], c_claimed)) goto fail;

    ensure_capacity(H);
    H->entries[H->size].handle = h_new;
    H->entries[H->size].ct = c_claimed;
    orhe_digest_ciphertext(H->entries[H->size].ct_digest, c_claimed);
    H->entries[H->size].is_base = 0;
    H->size += 1;

    for (int32_t i = 0; i < nwires; ++i) {
        if (wires[i]) orhe_delete_ciphertext(wires[i]);
    }
    std::free(wires);
    return 1;

fail:
    for (int32_t i = 0; i < nwires; ++i) {
        if (wires[i]) orhe_delete_ciphertext(wires[i]);
    }
    std::free(wires);
    return 0;
}

// --------------------------------------------------
// Compare proof path
// --------------------------------------------------

int32_t orhe_compare_server_prove(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    LweSample* c_sgn_out,
    LweSample* u_out,
    ORHEProof* pi_sgn_out,
    ORHEProof* pi_ks_out,
    const ORHEKeySet* ks
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return 0;

    ORHECiphertext* d = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    orhe_sub(d, e1->ct, e2->ct, &ks->data_sk->cloud);

    orhe_sign_bit(c_sgn_out, d, &ks->data_sk->cloud);
    orhe_switch_sign_to_cmp(u_out, c_sgn_out, ks);

    orhe_proof_prove_signext(pi_sgn_out, ks->signext_pp, d, c_sgn_out, ks->tfhe_params);
    orhe_proof_prove_ks(pi_ks_out, ks->ks_pp, c_sgn_out, u_out, ks->tfhe_params);

    orhe_delete_ciphertext(d);
    return 1;
}

int32_t orhe_gate_compare_verified(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi_sgn,
    const ORHEProof* pi_ks,
    const ORHEKeySet* ks
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return -1;

    ORHECiphertext* d = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    orhe_sub(d, e1->ct, e2->ct, &ks->data_sk->cloud);

    if (!orhe_proof_verify_signext(ks->signext_pp, d, c_sgn, pi_sgn, ks->tfhe_params)) {
        orhe_delete_ciphertext(d);
        return -1;
    }

    if (!orhe_proof_verify_ks(ks->ks_pp, c_sgn, u, pi_ks, ks->tfhe_params)) {
        orhe_delete_ciphertext(d);
        return -1;
    }

    Torus32 phase = lwePhase(u, ks->cmp_sk);
    int32_t sigma = (phase > 0) ? 1 : 0;

    orhe_delete_ciphertext(d);
    return sigma;
}

// Legacy compare kept for compatibility
int32_t orhe_gate_compare(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* claimed_cmp,
    const ORHEKeySet* ks
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return -1;

    ORHECiphertext* diff = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    orhe_sub(diff, e1->ct, e2->ct, &ks->data_sk->cloud);

    Torus32 phase = lwePhase(claimed_cmp, ks->cmp_sk);
    int32_t sigma = (phase > 0) ? 1 : 0;

    orhe_delete_ciphertext(diff);
    return sigma;
}

// added with metrics 
int32_t orhe_register_base_with_metrics(
    ORHEHandleTable* H,
    uint64_t h,
    ORHECiphertext* ct,
    const ORHEAuthSignature* sig,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    ORHETimer t;
    orhe_timer_start(&t);

    int32_t ok = orhe_register_base(H, h, ct, sig, ks);

    uint64_t elapsed = orhe_timer_elapsed_us(&t);

    if (m) {
        m->register_base_us += elapsed;
        m->end_to_end_online_us += elapsed;
        m->ciphertext_size_bytes += orhe_ciphertext_size_bytes(ct);
        m->metadata_size_bytes += sizeof(uint64_t) + 32 + sizeof(uint8_t);
        m->total_online_comm_bytes += orhe_ciphertext_size_bytes(ct) + sizeof(uint64_t) + 32;
        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    return ok;
}

int32_t orhe_register_derived_with_metrics(
    ORHEHandleTable* H,
    uint64_t h_new,
    const uint64_t* src_handles,
    int32_t nsrc,
    ORHECiphertext* c_claimed,
    const ORHECircuitTrace* tr,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    ORHETimer total_t, verify_t;
    orhe_timer_start(&total_t);

    // Approximate TFHE-side eval cost by replaying trace verifier-side glue + checkpoints path.
    // Since the current API receives only c_claimed + trace, the actual server-side raw TFHE eval
    // should ideally be timed at the caller when c_claimed is produced. We still keep this wrapper
    // for verifier-side decomposition.
    orhe_timer_start(&verify_t);
    int32_t ok = orhe_register_derived(H, h_new, src_handles, nsrc, c_claimed, tr, ks);
    uint64_t verify_us = orhe_timer_elapsed_us(&verify_t);
    uint64_t total_us = orhe_timer_elapsed_us(&total_t);

    uint64_t proof_bytes = 0;
    if (tr) {
        for (int32_t i = 0; i < tr->ncheckpoints; ++i) {
            proof_bytes += orhe_proof_size_bytes(&tr->checkpoints[i].proof);
        }
    }

    if (m) {
        m->register_derived_verifier_us += verify_us;
        m->verifier_us += verify_us;
        m->end_to_end_online_us += total_us;

        m->proof_size_bytes += proof_bytes;
        m->ciphertext_size_bytes += orhe_ciphertext_size_bytes(c_claimed);
        m->metadata_size_bytes += sizeof(uint64_t) + 32 + sizeof(uint8_t);

        // online communication for derived registration:
        // handles + claimed ciphertext + checkpoint proofs
        m->total_online_comm_bytes +=
            ((uint64_t) nsrc + 1) * sizeof(uint64_t) +
            orhe_ciphertext_size_bytes(c_claimed) +
            proof_bytes;

        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    return ok;
}

int32_t orhe_compare_server_prove_with_metrics(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    LweSample* c_sgn_out,
    LweSample* u_out,
    ORHEProof* pi_sgn_out,
    ORHEProof* pi_ks_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return 0;

    ORHETimer total_t, eval_t, prove_t;
    orhe_timer_start(&total_t);

    ORHECiphertext* d = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);

    orhe_timer_start(&eval_t);
    orhe_sub(d, e1->ct, e2->ct, &ks->data_sk->cloud);
    orhe_sign_bit(c_sgn_out, d, &ks->data_sk->cloud);
    orhe_switch_sign_to_cmp(u_out, c_sgn_out, ks);
    uint64_t eval_us = orhe_timer_elapsed_us(&eval_t);

    orhe_timer_start(&prove_t);
    orhe_proof_prove_signext(pi_sgn_out, ks->signext_pp, d, c_sgn_out, ks->tfhe_params);
    orhe_proof_prove_ks(pi_ks_out, ks->ks_pp, c_sgn_out, u_out, ks->tfhe_params);
    uint64_t prove_us = orhe_timer_elapsed_us(&prove_t);

    uint64_t total_us = orhe_timer_elapsed_us(&total_t);

    if (m) {
        m->tfhe_eval_us += eval_us;
        m->compare_tfhe_us += eval_us;

        m->prover_us += prove_us;
        m->compare_prover_us += prove_us;

        m->end_to_end_online_us += total_us;

        m->proof_size_bytes +=
            orhe_proof_size_bytes(pi_sgn_out) +
            orhe_proof_size_bytes(pi_ks_out);

        m->ciphertext_size_bytes +=
            orhe_ciphertext_size_bytes(d) +
            orhe_lwe_size_bytes(c_sgn_out, ks->tfhe_params->in_out_params) +
            orhe_lwe_size_bytes(u_out, ks->tfhe_params->in_out_params);

        m->metadata_size_bytes += 2 * sizeof(uint64_t);

        // server sends handles + c_sgn + u + both proofs
        m->total_online_comm_bytes +=
            2 * sizeof(uint64_t) +
            orhe_lwe_size_bytes(c_sgn_out, ks->tfhe_params->in_out_params) +
            orhe_lwe_size_bytes(u_out, ks->tfhe_params->in_out_params) +
            orhe_proof_size_bytes(pi_sgn_out) +
            orhe_proof_size_bytes(pi_ks_out);

        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    orhe_delete_ciphertext(d);
    return 1;
}

int32_t orhe_gate_compare_verified_with_metrics(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi_sgn,
    const ORHEProof* pi_ks,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return -1;

    ORHETimer total_t, verify_t;
    orhe_timer_start(&total_t);

    ORHECiphertext* d = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    orhe_sub(d, e1->ct, e2->ct, &ks->data_sk->cloud);

    orhe_timer_start(&verify_t);
    if (!orhe_proof_verify_signext(ks->signext_pp, d, c_sgn, pi_sgn, ks->tfhe_params)) {
        uint64_t verify_us = orhe_timer_elapsed_us(&verify_t);
        if (m) {
            m->verifier_us += verify_us;
            m->compare_verifier_us += verify_us;
            m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);
        }
        orhe_delete_ciphertext(d);
        return -1;
    }

    if (!orhe_proof_verify_ks(ks->ks_pp, c_sgn, u, pi_ks, ks->tfhe_params)) {
        uint64_t verify_us = orhe_timer_elapsed_us(&verify_t);
        if (m) {
            m->verifier_us += verify_us;
            m->compare_verifier_us += verify_us;
            m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);
        }
        orhe_delete_ciphertext(d);
        return -1;
    }
    uint64_t verify_us = orhe_timer_elapsed_us(&verify_t);

    Torus32 phase = lwePhase(u, ks->cmp_sk);
    int32_t sigma = (phase > 0) ? 1 : 0;

    if (m) {
        m->verifier_us += verify_us;
        m->compare_verifier_us += verify_us;
        m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);

        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    orhe_delete_ciphertext(d);
    return sigma;
}
