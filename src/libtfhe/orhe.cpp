#include "orhe.h"
#include "orhe_plonky2_backend.h"
#include "orhe_metrics.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <vector>

static const uint32_t ORHE_PBS_SEMANTIC_VERSION = 1u;
static const uint32_t ORHE_PBS_RELATION_SEMANTIC_KIND_STMT = 1u;
static const uint32_t ORHE_PBS_RELATION_SEMANTIC_KIND_WIT = 2u;
static const uint32_t ORHE_SUB_PARTIAL_VERSION = 1u;
static const uint32_t ORHE_SUB_PARTIAL_KIND_STMT = 1u;
static const uint32_t ORHE_SUB_PARTIAL_KIND_WIT = 2u;
static const uint32_t ORHE_SUB_RELATION_PARTIAL_RIPPLE = 1u;

static bool orhe_debug_compare_enabled() {
    const char* v = std::getenv("ORHE_DEBUG_COMPARE");
    return v && std::strcmp(v, "1") == 0;
}

static bool orhe_insecure_debug_api_enabled() {
    const char* v = std::getenv("ORHE_ENABLE_INSECURE_DEBUG_APIS");
    return v && std::strcmp(v, "1") == 0;
}

static const char* g_orhe_register_derived_last_error = "ok";

static void orhe_set_register_derived_error(const char* reason) {
    g_orhe_register_derived_last_error = reason ? reason : "unknown";
}

const char* orhe_register_derived_last_error(void) {
    return g_orhe_register_derived_last_error;
}

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

static void append_bytes_vec(std::vector<uint8_t>& out, const void* ptr, size_t len) {
    const uint8_t* p = (const uint8_t*) ptr;
    out.insert(out.end(), p, p + len);
}

static void serialize_lwe_into_vec(
    std::vector<uint8_t>& out,
    const LweSample* s,
    const LweParams* params
) {
    const int32_t n = params->n;
    append_bytes_vec(out, &n, sizeof(n));
    append_bytes_vec(out, &s->a[0], sizeof(Torus32) * (size_t) n);
    append_bytes_vec(out, &s->b, sizeof(Torus32));
    append_bytes_vec(out, &s->current_variance, sizeof(double));
}

static void serialize_ct_into_vec(std::vector<uint8_t>& out, const ORHECiphertext* ct) {
    append_bytes_vec(out, &ct->nbits, sizeof(ct->nbits));
    const int32_t n = ct->lwe_params->n;
    append_bytes_vec(out, &n, sizeof(n));
    for (int32_t i = 0; i < ct->nbits; ++i) {
        serialize_lwe_into_vec(out, &ct->bits[i], ct->lwe_params);
    }
}

static void append_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back((uint8_t) ((v >> (8 * i)) & 0xffu));
}

static void append_i32_le(std::vector<uint8_t>& out, int32_t v) {
    append_u32_le(out, (uint32_t) v);
}

static void append_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back((uint8_t) ((v >> (8 * i)) & 0xffu));
}

static void append_nested(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
    append_u64_le(out, (uint64_t) bytes.size());
    if (!bytes.empty()) append_bytes_vec(out, bytes.data(), bytes.size());
}

static void serialize_ct_binding_vec(std::vector<uint8_t>& out, const ORHECiphertext* ct) {
    append_i32_le(out, ct->nbits);
    append_i32_le(out, ct->lwe_params->n);
    for (int32_t bit = 0; bit < ct->nbits; ++bit) {
        const LweSample* s = &ct->bits[bit];
        for (int32_t i = 0; i < ct->lwe_params->n; ++i) append_i32_le(out, s->a[i]);
        append_i32_le(out, s->b);
        uint64_t var_bits = 0;
        std::memcpy(&var_bits, &s->current_variance, sizeof(var_bits));
        append_u64_le(out, var_bits);
    }
}

static int32_t orhe_pbs_semantic_relation_supported(int32_t relation) {
    return relation == ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE ||
           relation == ORHE_PBS_RELATION_T3_BITWISE_NOT ||
           relation == ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS ||
           relation == ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB;
}

static int32_t build_pbs_semantic_statement_and_witness(
    ORHEBytes* stmt_out,
    ORHEBytes* wit_out,
    int32_t relation,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEKeySet* ks
) {
    ORHETFHEContextId ctx;
    std::vector<uint8_t> x_bytes;
    std::vector<uint8_t> y_bytes;
    std::vector<uint8_t> stmt;
    std::vector<uint8_t> wit;

    stmt_out->ptr = NULL;
    stmt_out->len = 0;
    wit_out->ptr = NULL;
    wit_out->len = 0;

    if (!x_in || !y_out || !ks) return 0;
    ensure_same_width(x_in, y_out);
    if (!orhe_signext_build_tfhe_ctx_id(&ctx, ks)) return 0;

    serialize_ct_binding_vec(x_bytes, x_in);
    serialize_ct_binding_vec(y_bytes, y_out);

    append_bytes_vec(stmt, "OPBS", 4);
    append_u32_le(stmt, ORHE_PBS_SEMANTIC_VERSION);
    append_u32_le(stmt, ORHE_PBS_RELATION_SEMANTIC_KIND_STMT);
    append_u32_le(stmt, (uint32_t) relation);
    append_bytes_vec(stmt, &ctx, sizeof(ctx));
    append_nested(stmt, x_bytes);
    append_nested(stmt, y_bytes);

    append_bytes_vec(wit, "OPBS", 4);
    append_u32_le(wit, ORHE_PBS_SEMANTIC_VERSION);
    append_u32_le(wit, ORHE_PBS_RELATION_SEMANTIC_KIND_WIT);
    append_u32_le(wit, (uint32_t) relation);
    append_u32_le(wit, (uint32_t) x_in->nbits);
    append_u32_le(wit, (uint32_t) x_in->lwe_params->n);
    for (int32_t bit = 0; bit < x_in->nbits; ++bit) {
        for (int32_t i = 0; i < x_in->lwe_params->n; ++i) append_i32_le(wit, x_in->bits[bit].a[i]);
        append_i32_le(wit, x_in->bits[bit].b);
        for (int32_t i = 0; i < y_out->lwe_params->n; ++i) append_i32_le(wit, y_out->bits[bit].a[i]);
        append_i32_le(wit, y_out->bits[bit].b);
    }

    stmt_out->ptr = (uint8_t*) std::malloc(stmt.size());
    wit_out->ptr = (uint8_t*) std::malloc(wit.size());
    if (!stmt_out->ptr || !wit_out->ptr) {
        orhe_bytes_clear(stmt_out);
        orhe_bytes_clear(wit_out);
        return 0;
    }
    std::memcpy(stmt_out->ptr, stmt.data(), stmt.size());
    std::memcpy(wit_out->ptr, wit.data(), wit.size());
    stmt_out->len = (uint64_t) stmt.size();
    wit_out->len = (uint64_t) wit.size();
    return 1;
}

typedef struct {
    const uint8_t* diff_ptr;
    uint64_t diff_len;
    const uint8_t* trace_ptr;
    uint64_t trace_len;
    const uint8_t* backend_ptr;
    uint64_t backend_len;
} ORHESignExtCompareProofView;

typedef struct {
    const uint8_t* ptr;
    uint64_t len;
} ORHEProofSlice;

typedef struct {
    const uint8_t* signext_ptr;
    uint64_t signext_len;
    const uint8_t* ks_ptr;
    uint64_t ks_len;
} ORHECompareProofBundleView;

static int32_t read_u32_le(const uint8_t* ptr, size_t len, size_t* offset, uint32_t* out) {
    if (*offset + sizeof(uint32_t) > len) return 0;
    std::memcpy(out, ptr + *offset, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    return 1;
}

static int32_t read_u64_le(const uint8_t* ptr, size_t len, size_t* offset, uint64_t* out) {
    if (*offset + sizeof(uint64_t) > len) return 0;
    std::memcpy(out, ptr + *offset, sizeof(uint64_t));
    *offset += sizeof(uint64_t);
    return 1;
}

static std::vector<uint8_t> pack_compare_proof_bundle(
    const ORHEProof* signext_proof,
    const ORHEProof* ks_proof
) {
    std::vector<uint8_t> out;
    const uint32_t version = 1;
    const uint64_t signext_len =
        (signext_proof && signext_proof->blob && signext_proof->blob_len > 0) ? signext_proof->blob_len : 0;
    const uint64_t ks_len =
        (ks_proof && ks_proof->blob && ks_proof->blob_len > 0) ? ks_proof->blob_len : 0;
    append_bytes_vec(out, &version, sizeof(version));
    append_bytes_vec(out, &signext_len, sizeof(signext_len));
    append_bytes_vec(out, &ks_len, sizeof(ks_len));
    if (signext_len) append_bytes_vec(out, signext_proof->blob, (size_t) signext_len);
    if (ks_len) append_bytes_vec(out, ks_proof->blob, (size_t) ks_len);
    return out;
}

static int32_t unpack_compare_proof_bundle(
    const ORHEProof* proof,
    ORHECompareProofBundleView* out
) {
    if (!proof || !out || !proof->blob || proof->blob_len == 0) return 0;
    size_t offset = 0;
    uint32_t version = 0;
    uint64_t signext_len = 0;
    uint64_t ks_len = 0;
    const size_t total_len = (size_t) proof->blob_len;
    if (!read_u32_le(proof->blob, total_len, &offset, &version)) return 0;
    if (version != 1) return 0;
    if (!read_u64_le(proof->blob, total_len, &offset, &signext_len)) return 0;
    if (!read_u64_le(proof->blob, total_len, &offset, &ks_len)) return 0;
    if (offset + signext_len + ks_len != total_len) return 0;
    out->signext_ptr = proof->blob + offset;
    out->signext_len = signext_len;
    offset += (size_t) signext_len;
    out->ks_ptr = proof->blob + offset;
    out->ks_len = ks_len;
    return 1;
}

static ORHECiphertext* deserialize_ct_from_bytes(
    const uint8_t* ptr,
    size_t len,
    size_t* offset,
    const TFheGateBootstrappingParameterSet* params,
    int32_t expected_bit_width
) {
    int32_t nbits = 0;
    int32_t n = 0;
    if (*offset + sizeof(int32_t) * 2 > len) return NULL;
    std::memcpy(&nbits, ptr + *offset, sizeof(int32_t));
    *offset += sizeof(int32_t);
    std::memcpy(&n, ptr + *offset, sizeof(int32_t));
    *offset += sizeof(int32_t);

    if (nbits != expected_bit_width) return NULL;
    if (n != params->in_out_params->n) return NULL;

    ORHECiphertext* ct = orhe_new_ciphertext(nbits, params);
    for (int32_t i = 0; i < nbits; ++i) {
        int32_t bit_n = 0;
        if (*offset + sizeof(int32_t) > len) {
            orhe_delete_ciphertext(ct);
            return NULL;
        }
        std::memcpy(&bit_n, ptr + *offset, sizeof(int32_t));
        *offset += sizeof(int32_t);
        if (bit_n != n) {
            orhe_delete_ciphertext(ct);
            return NULL;
        }
        const size_t a_bytes = sizeof(Torus32) * (size_t) n;
        const size_t sample_bytes = a_bytes + sizeof(Torus32) + sizeof(double);
        if (*offset + sample_bytes > len) {
            orhe_delete_ciphertext(ct);
            return NULL;
        }
        std::memcpy(&ct->bits[i].a[0], ptr + *offset, a_bytes);
        *offset += a_bytes;
        std::memcpy(&ct->bits[i].b, ptr + *offset, sizeof(Torus32));
        *offset += sizeof(Torus32);
        std::memcpy(&ct->bits[i].current_variance, ptr + *offset, sizeof(double));
        *offset += sizeof(double);
    }
    return ct;
}

static std::vector<uint8_t> pack_signext_compare_proof_blob(
    const std::vector<uint8_t>& diff_bytes,
    const std::vector<uint8_t>& trace_bytes,
    const uint8_t* backend_ptr,
    uint64_t backend_len
) {
    std::vector<uint8_t> out;
    const uint32_t version = 1;
    append_bytes_vec(out, &version, sizeof(version));

    const uint64_t diff_len = (uint64_t) diff_bytes.size();
    const uint64_t trace_len = (uint64_t) trace_bytes.size();
    append_bytes_vec(out, &diff_len, sizeof(diff_len));
    append_bytes_vec(out, &trace_len, sizeof(trace_len));
    append_bytes_vec(out, &backend_len, sizeof(backend_len));
    if (diff_len) append_bytes_vec(out, diff_bytes.data(), (size_t) diff_len);
    if (trace_len) append_bytes_vec(out, trace_bytes.data(), (size_t) trace_len);
    if (backend_len) append_bytes_vec(out, backend_ptr, (size_t) backend_len);
    return out;
}

static std::vector<uint8_t> pack_checkpoint_proof_list(const std::vector<ORHEProof>& proofs) {
    std::vector<uint8_t> out;
    const uint32_t version = 1;
    const uint32_t count = (uint32_t) proofs.size();
    append_bytes_vec(out, &version, sizeof(version));
    append_bytes_vec(out, &count, sizeof(count));
    for (size_t i = 0; i < proofs.size(); ++i) {
        append_bytes_vec(out, &proofs[i].blob_len, sizeof(proofs[i].blob_len));
    }
    for (size_t i = 0; i < proofs.size(); ++i) {
        if (proofs[i].blob && proofs[i].blob_len > 0) {
            append_bytes_vec(out, proofs[i].blob, (size_t) proofs[i].blob_len);
        }
    }
    return out;
}

static int32_t unpack_checkpoint_proof_list(
    const uint8_t* ptr,
    uint64_t len,
    std::vector<ORHEProofSlice>* out
) {
    if (!ptr || !out) return 0;
    size_t offset = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    if (!read_u32_le(ptr, (size_t) len, &offset, &version)) return 0;
    if (version != 1) return 0;
    if (!read_u32_le(ptr, (size_t) len, &offset, &count)) return 0;

    std::vector<uint64_t> lengths;
    lengths.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t proof_len = 0;
        if (!read_u64_le(ptr, (size_t) len, &offset, &proof_len)) return 0;
        lengths.push_back(proof_len);
    }

    out->clear();
    out->reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (offset + lengths[i] > (size_t) len) return 0;
        ORHEProofSlice slice;
        slice.ptr = ptr + offset;
        slice.len = lengths[i];
        out->push_back(slice);
        offset += (size_t) lengths[i];
    }
    return offset == (size_t) len;
}

static int32_t unpack_signext_compare_proof_blob(
    const ORHEProof* proof,
    ORHESignExtCompareProofView* out
) {
    if (!proof || !out || !proof->blob || proof->blob_len == 0) return 0;

    size_t offset = 0;
    uint32_t version = 0;
    uint64_t diff_len = 0;
    uint64_t trace_len = 0;
    uint64_t backend_len = 0;
    const size_t total_len = (size_t) proof->blob_len;

    if (!read_u32_le(proof->blob, total_len, &offset, &version)) return 0;
    if (version != 1) return 0;
    if (!read_u64_le(proof->blob, total_len, &offset, &diff_len)) return 0;
    if (!read_u64_le(proof->blob, total_len, &offset, &trace_len)) return 0;
    if (!read_u64_le(proof->blob, total_len, &offset, &backend_len)) return 0;

    if (offset + diff_len + trace_len + backend_len != total_len) return 0;
    out->diff_ptr = proof->blob + offset;
    out->diff_len = diff_len;
    offset += (size_t) diff_len;
    out->trace_ptr = proof->blob + offset;
    out->trace_len = trace_len;
    offset += (size_t) trace_len;
    out->backend_ptr = proof->blob + offset;
    out->backend_len = backend_len;
    return 1;
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

static int32_t orhe_lwe_equal(const LweSample* a, const LweSample* b, const LweParams* params) {
    if (!a || !b) return 0;
    if (a->b != b->b) return 0;
    if (a->current_variance != b->current_variance) return 0;

    for (int32_t i = 0; i < params->n; ++i) {
        if (a->a[i] != b->a[i]) return 0;
    }

    return 1;
}

typedef struct {
    ORHECiphertext* diff;
    ORHECiphertext* b_not_bits;
    ORHECiphertext* xor_ab_bits;
    ORHECiphertext* and_ab_bits;
    ORHECiphertext* and_a_cin_bits;
    ORHECiphertext* and_b_cin_bits;
    ORHECiphertext* carry_or_bits;
    ORHECiphertext* carry_out_bits;
    LweSample* c_sgn;
    LweSample* u;
    uint8_t populated;
} ORHECompareExecutionTrace;

static void compare_trace_init(ORHECompareExecutionTrace* trace) {
    std::memset(trace, 0, sizeof(*trace));
}

static void compare_trace_delete(ORHECompareExecutionTrace* trace) {
    if (!trace) return;
    if (trace->diff) orhe_delete_ciphertext(trace->diff);
    if (trace->b_not_bits) orhe_delete_ciphertext(trace->b_not_bits);
    if (trace->xor_ab_bits) orhe_delete_ciphertext(trace->xor_ab_bits);
    if (trace->and_ab_bits) orhe_delete_ciphertext(trace->and_ab_bits);
    if (trace->and_a_cin_bits) orhe_delete_ciphertext(trace->and_a_cin_bits);
    if (trace->and_b_cin_bits) orhe_delete_ciphertext(trace->and_b_cin_bits);
    if (trace->carry_or_bits) orhe_delete_ciphertext(trace->carry_or_bits);
    if (trace->carry_out_bits) orhe_delete_ciphertext(trace->carry_out_bits);
    if (trace->c_sgn) delete_LweSample(trace->c_sgn);
    if (trace->u) delete_LweSample(trace->u);
    compare_trace_init(trace);
}

static int32_t compare_trace_prepare(
    ORHECompareExecutionTrace* trace,
    int32_t bit_width,
    const TFheGateBootstrappingParameterSet* tfhe_params,
    const LweParams* cmp_params
) {
    if (!trace) return 1;

    trace->diff = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->b_not_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->xor_ab_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->and_ab_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->and_a_cin_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->and_b_cin_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->carry_or_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->carry_out_bits = orhe_new_ciphertext(bit_width, tfhe_params);
    trace->c_sgn = new_LweSample(tfhe_params->in_out_params);
    trace->u = new_LweSample(cmp_params);
    trace->populated = 0;
    return 1;
}

static void append_bool_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& bits) {
    if (!bits.empty()) append_bytes_vec(out, bits.data(), bits.size());
}

static int32_t orhe_ciphertext_to_bit_vector(
    std::vector<uint8_t>* out,
    const ORHECiphertext* ct,
    const ORHEKeySet* ks
) {
    if (!out || !ct || !ks) return 0;
    out->clear();
    out->reserve((size_t) ct->nbits);
    for (int32_t i = 0; i < ct->nbits; ++i) {
        out->push_back((uint8_t) bootsSymDecrypt(&ct->bits[i], ks->data_sk));
    }
    return 1;
}

[[maybe_unused]] static int32_t build_sub_partial_statement_and_witness(
    ORHEBytes* stmt_out,
    ORHEBytes* wit_out,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHECompareExecutionTrace* trace,
    const ORHEKeySet* ks
) {
    ORHETFHEContextId ctx;
    std::vector<uint8_t> lhs_ser;
    std::vector<uint8_t> rhs_ser;
    std::vector<uint8_t> diff_ser;
    std::vector<uint8_t> stmt;
    std::vector<uint8_t> wit;
    std::vector<uint8_t> lhs_bits;
    std::vector<uint8_t> rhs_bits;
    std::vector<uint8_t> b_not_bits;
    std::vector<uint8_t> xor_ab_bits;
    std::vector<uint8_t> and_ab_bits;
    std::vector<uint8_t> and_a_cin_bits;
    std::vector<uint8_t> and_b_cin_bits;
    std::vector<uint8_t> carry_or_bits;
    std::vector<uint8_t> carry_out_bits;
    std::vector<uint8_t> diff_bits;

    stmt_out->ptr = NULL;
    stmt_out->len = 0;
    wit_out->ptr = NULL;
    wit_out->len = 0;

    if (!lhs || !rhs || !diff || !trace || !ks) return 0;
    ensure_same_width(lhs, rhs);
    ensure_same_width(lhs, diff);
    if (!trace->diff || !trace->b_not_bits || !trace->xor_ab_bits ||
        !trace->and_ab_bits || !trace->and_a_cin_bits || !trace->and_b_cin_bits ||
        !trace->carry_or_bits || !trace->carry_out_bits) {
        return 0;
    }
    if (!orhe_signext_build_tfhe_ctx_id(&ctx, ks)) return 0;

    serialize_ct_binding_vec(lhs_ser, lhs);
    serialize_ct_binding_vec(rhs_ser, rhs);
    serialize_ct_binding_vec(diff_ser, diff);

    if (!orhe_ciphertext_to_bit_vector(&lhs_bits, lhs, ks) ||
        !orhe_ciphertext_to_bit_vector(&rhs_bits, rhs, ks) ||
        !orhe_ciphertext_to_bit_vector(&b_not_bits, trace->b_not_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&xor_ab_bits, trace->xor_ab_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_ab_bits, trace->and_ab_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_a_cin_bits, trace->and_a_cin_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_b_cin_bits, trace->and_b_cin_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&carry_or_bits, trace->carry_or_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&carry_out_bits, trace->carry_out_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&diff_bits, diff, ks)) {
        return 0;
    }

    append_bytes_vec(stmt, "ORSB", 4);
    append_u32_le(stmt, ORHE_SUB_PARTIAL_VERSION);
    append_u32_le(stmt, ORHE_SUB_PARTIAL_KIND_STMT);
    append_u32_le(stmt, ORHE_SUB_RELATION_PARTIAL_RIPPLE);
    append_bytes_vec(stmt, &ctx, sizeof(ctx));
    append_nested(stmt, lhs_ser);
    append_nested(stmt, rhs_ser);
    append_nested(stmt, diff_ser);

    append_bytes_vec(wit, "ORSB", 4);
    append_u32_le(wit, ORHE_SUB_PARTIAL_VERSION);
    append_u32_le(wit, ORHE_SUB_PARTIAL_KIND_WIT);
    append_u32_le(wit, (uint32_t) lhs->nbits);
    append_bool_bytes(wit, lhs_bits);
    append_bool_bytes(wit, rhs_bits);
    append_bool_bytes(wit, b_not_bits);
    append_bool_bytes(wit, xor_ab_bits);
    append_bool_bytes(wit, and_ab_bits);
    append_bool_bytes(wit, and_a_cin_bits);
    append_bool_bytes(wit, and_b_cin_bits);
    append_bool_bytes(wit, carry_or_bits);
    append_bool_bytes(wit, carry_out_bits);
    append_bool_bytes(wit, diff_bits);

    stmt_out->ptr = (uint8_t*) std::malloc(stmt.size());
    wit_out->ptr = (uint8_t*) std::malloc(wit.size());
    if (!stmt_out->ptr || !wit_out->ptr) {
        orhe_bytes_clear(stmt_out);
        orhe_bytes_clear(wit_out);
        return 0;
    }
    std::memcpy(stmt_out->ptr, stmt.data(), stmt.size());
    std::memcpy(wit_out->ptr, wit.data(), wit.size());
    stmt_out->len = (uint64_t) stmt.size();
    wit_out->len = (uint64_t) wit.size();
    return 1;
}

static int32_t build_sub_partial_boolean_witness(
    ORHEBytes* wit_out,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHECompareExecutionTrace* trace,
    const ORHEKeySet* ks
) {
    std::vector<uint8_t> lhs_bits;
    std::vector<uint8_t> rhs_bits;
    std::vector<uint8_t> b_not_bits;
    std::vector<uint8_t> xor_ab_bits;
    std::vector<uint8_t> and_ab_bits;
    std::vector<uint8_t> and_a_cin_bits;
    std::vector<uint8_t> and_b_cin_bits;
    std::vector<uint8_t> carry_or_bits;
    std::vector<uint8_t> carry_out_bits;
    std::vector<uint8_t> diff_bits;
    std::vector<uint8_t> wit;

    wit_out->ptr = NULL;
    wit_out->len = 0;
    if (!lhs || !rhs || !diff || !trace || !ks) return 0;
    if (!orhe_ciphertext_to_bit_vector(&lhs_bits, lhs, ks) ||
        !orhe_ciphertext_to_bit_vector(&rhs_bits, rhs, ks) ||
        !orhe_ciphertext_to_bit_vector(&b_not_bits, trace->b_not_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&xor_ab_bits, trace->xor_ab_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_ab_bits, trace->and_ab_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_a_cin_bits, trace->and_a_cin_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&and_b_cin_bits, trace->and_b_cin_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&carry_or_bits, trace->carry_or_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&carry_out_bits, trace->carry_out_bits, ks) ||
        !orhe_ciphertext_to_bit_vector(&diff_bits, diff, ks)) {
        return 0;
    }

    append_u32_le(wit, 1u);
    append_u32_le(wit, (uint32_t) lhs->nbits);
    append_bool_bytes(wit, lhs_bits);
    append_bool_bytes(wit, rhs_bits);
    append_bool_bytes(wit, b_not_bits);
    append_bool_bytes(wit, xor_ab_bits);
    append_bool_bytes(wit, and_ab_bits);
    append_bool_bytes(wit, and_a_cin_bits);
    append_bool_bytes(wit, and_b_cin_bits);
    append_bool_bytes(wit, carry_or_bits);
    append_bool_bytes(wit, carry_out_bits);
    append_bool_bytes(wit, diff_bits);
    wit.push_back(diff_bits.empty() ? 0u : diff_bits.back());

    wit_out->ptr = (uint8_t*) std::malloc(wit.size());
    if (!wit_out->ptr) {
        orhe_bytes_clear(wit_out);
        return 0;
    }
    std::memcpy(wit_out->ptr, wit.data(), wit.size());
    wit_out->len = (uint64_t) wit.size();
    return 1;
}

static std::vector<uint8_t> serialize_compare_execution_trace(
    const ORHECompareExecutionTrace* trace
) {
    std::vector<uint8_t> out;
    const uint32_t version = 1;
    append_bytes_vec(out, &version, sizeof(version));

    if (!trace || !trace->populated) {
        return out;
    }

    serialize_ct_into_vec(out, trace->b_not_bits);
    serialize_ct_into_vec(out, trace->xor_ab_bits);
    serialize_ct_into_vec(out, trace->and_ab_bits);
    serialize_ct_into_vec(out, trace->and_a_cin_bits);
    serialize_ct_into_vec(out, trace->and_b_cin_bits);
    serialize_ct_into_vec(out, trace->carry_or_bits);
    serialize_ct_into_vec(out, trace->carry_out_bits);
    return out;
}

static int32_t validate_compare_execution_trace_bytes(
    const uint8_t* ptr,
    uint64_t len,
    const TFheGateBootstrappingParameterSet* params,
    int32_t expected_bit_width
) {
    if (!ptr || len < sizeof(uint32_t)) return 0;

    size_t offset = 0;
    uint32_t version = 0;
    if (!read_u32_le(ptr, (size_t) len, &offset, &version)) return 0;
    if (version != 1) return 0;

    for (int i = 0; i < 7; ++i) {
        ORHECiphertext* ct = deserialize_ct_from_bytes(
            ptr,
            (size_t) len,
            &offset,
            params,
            expected_bit_width
        );
        if (!ct) return 0;
        orhe_delete_ciphertext(ct);
    }

    return offset == (size_t) len;
}

static int32_t deserialize_compare_execution_trace_bytes(
    ORHECompareExecutionTrace* out,
    const uint8_t* ptr,
    uint64_t len,
    const TFheGateBootstrappingParameterSet* params,
    int32_t expected_bit_width
) {
    if (!out) return 0;
    compare_trace_init(out);
    if (!compare_trace_prepare(out, expected_bit_width, params, params->in_out_params)) {
        return 0;
    }

    size_t offset = 0;
    uint32_t version = 0;
    if (!read_u32_le(ptr, (size_t) len, &offset, &version)) {
        compare_trace_delete(out);
        return 0;
    }
    if (version != 1) {
        compare_trace_delete(out);
        return 0;
    }

    ORHECiphertext** fields[7] = {
        &out->b_not_bits,
        &out->xor_ab_bits,
        &out->and_ab_bits,
        &out->and_a_cin_bits,
        &out->and_b_cin_bits,
        &out->carry_or_bits,
        &out->carry_out_bits
    };

    for (int i = 0; i < 7; ++i) {
        ORHECiphertext* ct = deserialize_ct_from_bytes(ptr, (size_t) len, &offset, params, expected_bit_width);
        if (!ct) {
            compare_trace_delete(out);
            return 0;
        }
        orhe_delete_ciphertext(*fields[i]);
        *fields[i] = ct;
    }

    out->populated = 1;
    return offset == (size_t) len;
}

static ORHECiphertext* make_ciphertext_from_samples(
    int32_t nbits,
    const LweSample* const* samples,
    const TFheGateBootstrappingParameterSet* params
) {
    ORHECiphertext* ct = orhe_new_ciphertext(nbits, params);
    for (int32_t i = 0; i < nbits; ++i) {
        lweCopy(&ct->bits[i], samples[i], ct->lwe_params);
    }
    return ct;
}

static ORHECiphertext* make_single_bit_ciphertext(
    const LweSample* sample,
    const TFheGateBootstrappingParameterSet* params
) {
    const LweSample* samples[1] = { sample };
    return make_ciphertext_from_samples(1, samples, params);
}

static ORHECiphertext* make_two_bit_ciphertext(
    const LweSample* lhs,
    const LweSample* rhs,
    const TFheGateBootstrappingParameterSet* params
) {
    const LweSample* samples[2] = { lhs, rhs };
    return make_ciphertext_from_samples(2, samples, params);
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

static void orhe_sub_with_trace(
    ORHECiphertext* out,
    const ORHECiphertext* a,
    const ORHECiphertext* b,
    const TFheGateBootstrappingCloudKeySet* bk,
    ORHECompareExecutionTrace* trace,
    uint64_t* witness_copy_us_out
) {
    if (!trace) {
        orhe_sub(out, a, b, bk);
        if (witness_copy_us_out) *witness_copy_us_out = 0;
        return;
    }

    ensure_same_width(a, b);
    if (out->nbits != a->nbits) {
        throw std::runtime_error("orhe_sub_with_trace width mismatch");
    }

    const TFheGateBootstrappingParameterSet* params = bk->params;
    LweSample* carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* b_not = new_gate_bootstrapping_ciphertext(params);
    LweSample* next_carry = new_gate_bootstrapping_ciphertext(params);
    LweSample* t1 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t2 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t3 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t4 = new_gate_bootstrapping_ciphertext(params);
    LweSample* t5 = new_gate_bootstrapping_ciphertext(params);
    uint64_t witness_copy_us = 0;

    bootsCONSTANT(carry, 1, bk);

    for (int32_t i = 0; i < a->nbits; ++i) {
        bootsNOT(b_not, &b->bits[i], bk);
        bootsXOR(t1, &a->bits[i], b_not, bk);
        bootsXOR(&out->bits[i], t1, carry, bk);

        bootsAND(t2, &a->bits[i], b_not, bk);
        bootsAND(t3, &a->bits[i], carry, bk);
        bootsAND(t4, b_not, carry, bk);
        bootsOR(t5, t2, t3, bk);
        bootsOR(next_carry, t5, t4, bk);

        ORHETimer copy_t;
        orhe_timer_start(&copy_t);
        lweCopy(&trace->diff->bits[i], &out->bits[i], out->lwe_params);
        lweCopy(&trace->b_not_bits->bits[i], b_not, out->lwe_params);
        lweCopy(&trace->xor_ab_bits->bits[i], t1, out->lwe_params);
        lweCopy(&trace->and_ab_bits->bits[i], t2, out->lwe_params);
        lweCopy(&trace->and_a_cin_bits->bits[i], t3, out->lwe_params);
        lweCopy(&trace->and_b_cin_bits->bits[i], t4, out->lwe_params);
        lweCopy(&trace->carry_or_bits->bits[i], t5, out->lwe_params);
        lweCopy(&trace->carry_out_bits->bits[i], next_carry, out->lwe_params);
        witness_copy_us += orhe_timer_elapsed_us(&copy_t);

        bootsCOPY(carry, next_carry, bk);
    }

    delete_gate_bootstrapping_ciphertext(t5);
    delete_gate_bootstrapping_ciphertext(t4);
    delete_gate_bootstrapping_ciphertext(t3);
    delete_gate_bootstrapping_ciphertext(t2);
    delete_gate_bootstrapping_ciphertext(t1);
    delete_gate_bootstrapping_ciphertext(next_carry);
    delete_gate_bootstrapping_ciphertext(b_not);
    delete_gate_bootstrapping_ciphertext(carry);
    if (witness_copy_us_out) *witness_copy_us_out = witness_copy_us;
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
    pp->backend_mode = ORHE_BACKEND_MODE_REFERENCE;
    pp->backend = (ORHEBackendHandle*) orhe_backend_setup_bridge(family, bit_width);
    return pp;
}

ORHEProofPP* orhe_proof_setup_pbs_semantic(int32_t bit_width, int32_t lwe_n) {
    ORHEProofPP* pp = (ORHEProofPP*) std::malloc(sizeof(ORHEProofPP));
    pp->family = ORHE_PROOF_FAMILY_PBS;
    pp->bit_width = bit_width;
    pp->backend_mode = ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC;
    pp->backend = (ORHEBackendHandle*) orhe_backend_setup_pbs_semantic_bridge(bit_width, lwe_n);
    return pp;
}

ORHEProofPP* orhe_proof_setup_signext_semantic(int32_t bit_width) {
    ORHEProofPP* pp = (ORHEProofPP*) std::malloc(sizeof(ORHEProofPP));
    pp->family = ORHE_PROOF_FAMILY_SIGNEXT;
    pp->bit_width = bit_width;
    pp->backend_mode = ORHE_BACKEND_MODE_SIGNEXT_PARTIAL_SEMANTIC_B1_B3;
    pp->backend = (ORHEBackendHandle*) orhe_backend_setup_signext_semantic_bridge(bit_width);
    return pp;
}

ORHEProofPP* orhe_proof_setup_sub_partial(int32_t bit_width) {
    ORHEProofPP* pp = (ORHEProofPP*) std::malloc(sizeof(ORHEProofPP));
    pp->family = ORHE_PROOF_FAMILY_SUB;
    pp->bit_width = bit_width;
    pp->backend_mode = ORHE_BACKEND_MODE_SUB_PARTIAL_TRACE;
    pp->backend = (ORHEBackendHandle*) orhe_backend_setup_bridge(ORHE_PROOF_FAMILY_SIGNEXT, bit_width);
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

void orhe_proof_prove_pbs_relation(
    ORHEProof* out,
    const ORHEProofPP* pp,
    int32_t relation,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEKeySet* ks
) {
    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (!pp || !x_in || !y_out) return;

    if (pp->backend_mode == ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC &&
        orhe_pbs_semantic_relation_supported(relation)) {
        ORHEBytes stmt;
        ORHEBytes wit;
        stmt.ptr = NULL;
        stmt.len = 0;
        wit.ptr = NULL;
        wit.len = 0;
        if (!build_pbs_semantic_statement_and_witness(&stmt, &wit, relation, x_in, y_out, ks)) {
            orhe_bytes_clear(&stmt);
            orhe_bytes_clear(&wit);
            return;
        }
        if (orhe_backend_prove_pbs_semantic_bridge(
                (void*) pp->backend,
                stmt.ptr,
                stmt.len,
                wit.ptr,
                wit.len,
                &out->blob,
                &out->blob_len)) {
            out->family = ORHE_PROOF_FAMILY_PBS;
            out->owns_backend_buffer = 1;
        }
        orhe_bytes_clear(&stmt);
        orhe_bytes_clear(&wit);
        return;
    }

    if (pp->backend_mode == ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC) return;

    orhe_proof_prove_pbs(out, pp, x_in, y_out);
}

int32_t orhe_proof_verify_pbs_relation(
    const ORHEProofPP* pp,
    int32_t relation,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const ORHEProof* proof,
    const ORHEKeySet* ks
) {
    if (!pp || !proof || proof->family != ORHE_PROOF_FAMILY_PBS) return 0;

    if (pp->backend_mode == ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC &&
        orhe_pbs_semantic_relation_supported(relation)) {
        ORHEBytes stmt;
        ORHEBytes wit;
        stmt.ptr = NULL;
        stmt.len = 0;
        wit.ptr = NULL;
        wit.len = 0;
        int32_t ok = 0;
        if (build_pbs_semantic_statement_and_witness(&stmt, &wit, relation, x_in, y_out, ks)) {
            ok = orhe_backend_verify_pbs_semantic_bridge(
                (void*) pp->backend,
                stmt.ptr,
                stmt.len,
                wit.ptr,
                wit.len,
                proof->blob,
                proof->blob_len
            );
        }
        orhe_bytes_clear(&stmt);
        orhe_bytes_clear(&wit);
        return ok;
    }

    if (pp->backend_mode == ORHE_BACKEND_MODE_PBS_RELATION_SEMANTIC) return 0;

    return orhe_proof_verify_pbs(pp, x_in, y_out, proof);
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
            NULL,
            0,
            NULL,
            0,
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
        NULL,
        0,
        params,
        proof->blob,
        proof->blob_len
    );
}

void orhe_proof_prove_sub_partial(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHEKeySet* ks
) {
    ORHECompareExecutionTrace trace;
    ORHECiphertext* expected = NULL;
    ORHEBytes wit;
    std::vector<uint8_t> trace_bytes;
    std::memset(&trace, 0, sizeof(trace));
    wit.ptr = NULL;
    wit.len = 0;

    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (!pp || !lhs || !rhs || !diff || !ks ||
        pp->backend_mode != ORHE_BACKEND_MODE_SUB_PARTIAL_TRACE) {
        return;
    }

    if (!compare_trace_prepare(&trace, lhs->nbits, ks->tfhe_params, ks->cmp_sk->params)) {
        return;
    }

    expected = orhe_new_ciphertext(lhs->nbits, ks->tfhe_params);
    orhe_sub_with_trace(expected, lhs, rhs, &ks->data_sk->cloud, &trace, NULL);
    trace_bytes = serialize_compare_execution_trace(&trace);
    if (!orhe_ct_equal(expected, diff) ||
        !build_sub_partial_boolean_witness(&wit, lhs, rhs, diff, &trace, ks)) {
        orhe_delete_ciphertext(expected);
        compare_trace_delete(&trace);
        orhe_bytes_clear(&wit);
        return;
    }

    if (orhe_backend_prove_signext_bridge(
            (void*) pp->backend,
            diff,
            &diff->bits[diff->nbits - 1],
            trace_bytes.data(),
            (uint64_t) trace_bytes.size(),
            wit.ptr,
            wit.len,
            ks->tfhe_params,
            &out->blob,
            &out->blob_len)) {
        out->family = ORHE_PROOF_FAMILY_SUB;
        out->owns_backend_buffer = 1;
    }

    orhe_delete_ciphertext(expected);
    compare_trace_delete(&trace);
    orhe_bytes_clear(&wit);
}

int32_t orhe_proof_verify_sub_partial(
    const ORHEProofPP* pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECiphertext* diff,
    const ORHEProof* proof,
    const ORHEKeySet* ks
) {
    ORHECompareExecutionTrace trace;
    ORHECiphertext* expected = NULL;
    ORHEBytes wit;
    std::vector<uint8_t> trace_bytes;
    int32_t ok = 0;
    std::memset(&trace, 0, sizeof(trace));
    wit.ptr = NULL;
    wit.len = 0;

    if (!pp || !lhs || !rhs || !diff || !proof || !ks ||
        proof->family != ORHE_PROOF_FAMILY_SUB ||
        pp->backend_mode != ORHE_BACKEND_MODE_SUB_PARTIAL_TRACE) {
        return 0;
    }

    if (!compare_trace_prepare(&trace, lhs->nbits, ks->tfhe_params, ks->cmp_sk->params)) {
        return 0;
    }

    expected = orhe_new_ciphertext(lhs->nbits, ks->tfhe_params);
    orhe_sub_with_trace(expected, lhs, rhs, &ks->data_sk->cloud, &trace, NULL);
    trace_bytes = serialize_compare_execution_trace(&trace);
    if (orhe_ct_equal(expected, diff) &&
        build_sub_partial_boolean_witness(&wit, lhs, rhs, diff, &trace, ks)) {
        ok = orhe_backend_verify_signext_bridge(
            (void*) pp->backend,
            diff,
            &diff->bits[diff->nbits - 1],
            trace_bytes.data(),
            (uint64_t) trace_bytes.size(),
            ks->tfhe_params,
            proof->blob,
            proof->blob_len
        );
    }

    orhe_delete_ciphertext(expected);
    compare_trace_delete(&trace);
    orhe_bytes_clear(&wit);
    return ok;
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
    out->reg_pbs_pp = orhe_proof_setup_pbs_semantic(params->bit_width, p->in_out_params->n);
    out->signext_pp = orhe_proof_setup_signext_semantic(params->bit_width);
    out->sub_pp = orhe_proof_setup_sub_partial(params->bit_width);
    out->ks_pp = orhe_proof_setup(ORHE_PROOF_FAMILY_KS, params->bit_width);

    return out;
}

void orhe_delete_keyset(ORHEKeySet* ks) {
    if (!ks) return;

    orhe_proof_pp_delete(ks->pbs_pp);
    orhe_proof_pp_delete(ks->reg_pbs_pp);
    orhe_proof_pp_delete(ks->signext_pp);
    orhe_proof_pp_delete(ks->sub_pp);
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

void orhe_shr(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int32_t shift,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    if (!out || !in || !bk) return;
    if (shift <= 0) {
        orhe_copy(out, in, bk);
        return;
    }

    for (int32_t i = 0; i < out->nbits; ++i) {
        const int32_t src_bit = i + shift;
        if (src_bit < in->nbits) {
            bootsCOPY(&out->bits[i], &in->bits[src_bit], bk);
        } else {
            bootsCONSTANT(&out->bits[i], 0, bk);
        }
    }
}

static void orhe_copy_low_bits_and_zero_rest(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int32_t keep_bits,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    if (!out || !in || !bk) return;
    if (out->nbits != in->nbits) {
        throw std::runtime_error("orhe_copy_low_bits_and_zero_rest width mismatch");
    }
    for (int32_t i = 0; i < in->nbits; ++i) {
        if (i < keep_bits) {
            bootsCOPY(&out->bits[i], &in->bits[i], bk);
        } else {
            bootsCONSTANT(&out->bits[i], 0, bk);
        }
    }
}

static void orhe_extract_msb_to_lsb_direct(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    if (!out || !in || !bk) return;
    if (out->nbits != in->nbits) {
        throw std::runtime_error("orhe_extract_msb_to_lsb_direct width mismatch");
    }
    if (in->nbits <= 0) return;
    bootsCOPY(&out->bits[0], &in->bits[in->nbits - 1], bk);
    for (int32_t i = 1; i < out->nbits; ++i) {
        bootsCONSTANT(&out->bits[i], 0, bk);
    }
}

int32_t orhe_eval_allowed_pbs_relation(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int32_t relation,
    const ORHEKeySet* ks
) {
    if (!out || !in || !ks) return 0;

    int32_t ok = 1;

    switch (relation) {
        case ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE:
            orhe_copy_low_bits_and_zero_rest(out, in, 4, &ks->data_sk->cloud);
            break;

        case ORHE_PBS_RELATION_T3_BITWISE_NOT:
            orhe_not(out, in, &ks->data_sk->cloud);
            break;

        case ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS:
            orhe_copy_low_bits_and_zero_rest(out, in, 2, &ks->data_sk->cloud);
            break;

        case ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB:
            orhe_extract_msb_to_lsb_direct(out, in, &ks->data_sk->cloud);
            break;

        default:
            ok = 0;
            break;
    }
    return ok;
}

void orhe_sign_bit(
    LweSample* out_sign,
    const ORHECiphertext* diff,
    const TFheGateBootstrappingCloudKeySet* bk
) {
    // SignExt is implemented as one PBS on the sign wire. In TFHE this
    // bootstrap includes the standard accumulator init, blind rotation,
    // extraction, and internal key switch. The compare-domain KS remains an
    // explicit separate step below.
    static const Torus32 MU = modSwitchToTorus32(1, 8);
    const LweSample* pbs_input = &diff->bits[diff->nbits - 1];
    const LweBootstrappingKeyFFT* bk_fft = bk->bkFFT;
    const TGswParams* bk_params = bk_fft->bk_params;
    const TLweParams* accum_params = bk_fft->accum_params;
    const LweParams* extract_params = &accum_params->extracted_lweparams;
    const int32_t N = accum_params->N;
    const int32_t two_n = 2 * N;
    const int32_t n = bk_fft->in_out_params->n;

    TorusPolynomial* testvect = new_TorusPolynomial(N);
    TorusPolynomial* rotated = new_TorusPolynomial(N);
    TLweSample* accum = new_TLweSample(accum_params);
    LweSample* pre_ks = new_LweSample(extract_params);
    int32_t* bara = new int32_t[n];

    const int32_t barb = modSwitchFromTorus32(pbs_input->b, two_n);
    for (int32_t i = 0; i < N; ++i) testvect->coefsT[i] = MU;
    if (barb != 0) torusPolynomialMulByXai(rotated, two_n - barb, testvect);
    else torusPolynomialCopy(rotated, testvect);
    tLweNoiselessTrivial(accum, rotated, accum_params);

    for (int32_t i = 0; i < n; ++i) {
        bara[i] = modSwitchFromTorus32(pbs_input->a[i], two_n);
    }
    tfhe_blindRotate_FFT(accum, bk_fft->bkFFT, bara, n, bk_params);
    tLweExtractLweSample(pre_ks, accum, extract_params, accum_params);
    lweKeySwitch(out_sign, bk_fft->ks, pre_ks);

    delete[] bara;
    delete_LweSample(pre_ks);
    delete_TLweSample(accum);
    delete_TorusPolynomial(rotated);
    delete_TorusPolynomial(testvect);
}

void orhe_switch_sign_to_cmp(
    LweSample* out_cmp,
    const LweSample* sign_bit_data_domain,
    const ORHEKeySet* ks
) {
    lweKeySwitch(out_cmp, ks->data_to_cmp_ks, sign_bit_data_domain);
}

static uint64_t orhe_sign_bit_with_metrics(
    LweSample* out_sign,
    const ORHECiphertext* diff,
    const TFheGateBootstrappingCloudKeySet* bk,
    ORHEMetrics* m
) {
    if (!m) {
        orhe_sign_bit(out_sign, diff, bk);
        return 0;
    }

    static const Torus32 MU = modSwitchToTorus32(1, 8);
    const LweSample* pbs_input = &diff->bits[diff->nbits - 1];
    const LweBootstrappingKeyFFT* bk_fft = bk->bkFFT;
    const TGswParams* bk_params = bk_fft->bk_params;
    const TLweParams* accum_params = bk_fft->accum_params;
    const LweParams* extract_params = &accum_params->extracted_lweparams;
    const int32_t N = accum_params->N;
    const int32_t two_n = 2 * N;
    const int32_t n = bk_fft->in_out_params->n;

    TorusPolynomial* testvect = new_TorusPolynomial(N);
    TorusPolynomial* rotated = new_TorusPolynomial(N);
    TLweSample* accum = new_TLweSample(accum_params);
    LweSample* pre_ks = new_LweSample(extract_params);
    int32_t* bara = new int32_t[n];

    const int32_t barb = modSwitchFromTorus32(pbs_input->b, two_n);

    ORHETimer t;
    uint64_t pbs_total_us = 0;

    orhe_timer_start(&t);
    for (int32_t i = 0; i < N; ++i) testvect->coefsT[i] = MU;
    if (barb != 0) torusPolynomialMulByXai(rotated, two_n - barb, testvect);
    else torusPolynomialCopy(rotated, testvect);
    tLweNoiselessTrivial(accum, rotated, accum_params);
    {
        const uint64_t stage_us = orhe_timer_elapsed_us(&t);
        m->accum_init_us += stage_us;
        pbs_total_us += stage_us;
    }

    for (int32_t i = 0; i < n; ++i) {
        bara[i] = modSwitchFromTorus32(pbs_input->a[i], two_n);
    }

    orhe_timer_start(&t);
    tfhe_blindRotate_FFT(accum, bk_fft->bkFFT, bara, n, bk_params);
    {
        const uint64_t stage_us = orhe_timer_elapsed_us(&t);
        m->blind_rotate_us += stage_us;
        pbs_total_us += stage_us;
    }

    orhe_timer_start(&t);
    tLweExtractLweSample(pre_ks, accum, extract_params, accum_params);
    {
        const uint64_t stage_us = orhe_timer_elapsed_us(&t);
        m->extract_us += stage_us;
        pbs_total_us += stage_us;
    }

    orhe_timer_start(&t);
    lweKeySwitch(out_sign, bk_fft->ks, pre_ks);
    {
        const uint64_t stage_us = orhe_timer_elapsed_us(&t);
        m->exec_internal_ks_us += stage_us;
        pbs_total_us += stage_us;
    }
    m->exec_signbit_pbs_us += pbs_total_us;

    delete[] bara;
    delete_LweSample(pre_ks);
    delete_TLweSample(accum);
    delete_TorusPolynomial(rotated);
    delete_TorusPolynomial(testvect);
    return pbs_total_us;
}

static void orhe_compare_tfhe_path_with_metrics(
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    ORHECiphertext* diff_out,
    LweSample* c_sgn_out,
    LweSample* u_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m,
    ORHECompareExecutionTrace* trace
) {
    if (m) {
        ORHETimer stage_t;
        uint64_t witness_copy_us = 0;
        orhe_timer_start(&stage_t);
        orhe_sub_with_trace(diff_out, lhs, rhs, &ks->data_sk->cloud, trace, &witness_copy_us);
        uint64_t sub_us = orhe_timer_elapsed_us(&stage_t);
        if (sub_us >= witness_copy_us) sub_us -= witness_copy_us;
        m->exec_subtraction_us += sub_us;

        const uint64_t pbs_us = orhe_sign_bit_with_metrics(c_sgn_out, diff_out, &ks->data_sk->cloud, m);
        if (trace) {
            lweCopy(trace->c_sgn, c_sgn_out, ks->tfhe_params->in_out_params);
        }

        orhe_timer_start(&stage_t);
        orhe_switch_sign_to_cmp(u_out, c_sgn_out, ks);
        const uint64_t final_cmp_ks_us = orhe_timer_elapsed_us(&stage_t);
        m->exec_final_cmp_ks_us += final_cmp_ks_us;
        if (trace) {
            lweCopy(trace->u, u_out, ks->cmp_sk->params);
            trace->populated = 1;
        }

        const uint64_t exec_us = sub_us + pbs_us + final_cmp_ks_us;
        m->exec_tfhe_us += exec_us;
        m->compare_tfhe_us += exec_us;
        return;
    }

    orhe_sub_with_trace(diff_out, lhs, rhs, &ks->data_sk->cloud, trace, NULL);
    orhe_sign_bit(c_sgn_out, diff_out, &ks->data_sk->cloud);
    if (trace) {
        lweCopy(trace->c_sgn, c_sgn_out, ks->tfhe_params->in_out_params);
    }
    orhe_switch_sign_to_cmp(u_out, c_sgn_out, ks);
    if (trace) {
        lweCopy(trace->u, u_out, ks->cmp_sk->params);
        trace->populated = 1;
    }
}

[[maybe_unused]] static void orhe_proof_prove_signext_from_execution_trace(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const ORHECompareExecutionTrace* trace,
    const ORHEKeySet* ks
) {
    if (!trace || !trace->populated || !trace->diff || !trace->c_sgn) {
        out->family = ORHE_PROOF_FAMILY_NONE;
        out->blob = NULL;
        out->blob_len = 0;
        out->owns_backend_buffer = 0;
        return;
    }

    // Compare execution materializes the subtraction transcript once. The
    // prover packages a sequence of PBS checkpoints over that saved
    // subtraction/signbit transcript instead of rebuilding the subtractor.
    const std::vector<uint8_t> diff_bytes = [&]() {
        std::vector<uint8_t> bytes;
        serialize_ct_into_vec(bytes, trace->diff);
        return bytes;
    }();
    const std::vector<uint8_t> trace_bytes = serialize_compare_execution_trace(trace);
    std::vector<ORHEProof> checkpoint_proofs;
    checkpoint_proofs.reserve((size_t) (lhs->nbits * 7 + 1));

    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    for (int32_t i = 0; i < lhs->nbits; ++i) {
        const LweSample* carry_in = (i == 0) ? NULL : &trace->carry_out_bits->bits[i - 1];
        LweSample* carry_const = NULL;
        if (i == 0) {
            carry_const = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
            bootsCONSTANT(carry_const, 1, &ks->data_sk->cloud);
            carry_in = carry_const;
        }

        ORHEProof proof;

        ORHECiphertext* x_xor_ab = make_two_bit_ciphertext(&lhs->bits[i], &trace->b_not_bits->bits[i], ks->tfhe_params);
        ORHECiphertext* y_xor_ab = make_single_bit_ciphertext(&trace->xor_ab_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_xor_ab, y_xor_ab);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_xor_ab);
        orhe_delete_ciphertext(y_xor_ab);

        ORHECiphertext* x_diff = make_two_bit_ciphertext(&trace->xor_ab_bits->bits[i], carry_in, ks->tfhe_params);
        ORHECiphertext* y_diff = make_single_bit_ciphertext(&trace->diff->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_diff, y_diff);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_diff);
        orhe_delete_ciphertext(y_diff);

        ORHECiphertext* x_and_ab = make_two_bit_ciphertext(&lhs->bits[i], &trace->b_not_bits->bits[i], ks->tfhe_params);
        ORHECiphertext* y_and_ab = make_single_bit_ciphertext(&trace->and_ab_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_and_ab, y_and_ab);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_and_ab);
        orhe_delete_ciphertext(y_and_ab);

        ORHECiphertext* x_and_a_cin = make_two_bit_ciphertext(&lhs->bits[i], carry_in, ks->tfhe_params);
        ORHECiphertext* y_and_a_cin = make_single_bit_ciphertext(&trace->and_a_cin_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_and_a_cin, y_and_a_cin);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_and_a_cin);
        orhe_delete_ciphertext(y_and_a_cin);

        ORHECiphertext* x_and_b_cin = make_two_bit_ciphertext(&trace->b_not_bits->bits[i], carry_in, ks->tfhe_params);
        ORHECiphertext* y_and_b_cin = make_single_bit_ciphertext(&trace->and_b_cin_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_and_b_cin, y_and_b_cin);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_and_b_cin);
        orhe_delete_ciphertext(y_and_b_cin);

        ORHECiphertext* x_carry_or = make_two_bit_ciphertext(&trace->and_ab_bits->bits[i], &trace->and_a_cin_bits->bits[i], ks->tfhe_params);
        ORHECiphertext* y_carry_or = make_single_bit_ciphertext(&trace->carry_or_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_carry_or, y_carry_or);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_carry_or);
        orhe_delete_ciphertext(y_carry_or);

        ORHECiphertext* x_carry_out = make_two_bit_ciphertext(&trace->carry_or_bits->bits[i], &trace->and_b_cin_bits->bits[i], ks->tfhe_params);
        ORHECiphertext* y_carry_out = make_single_bit_ciphertext(&trace->carry_out_bits->bits[i], ks->tfhe_params);
        orhe_proof_prove_pbs(&proof, ks->pbs_pp, x_carry_out, y_carry_out);
        checkpoint_proofs.push_back(proof);
        orhe_delete_ciphertext(x_carry_out);
        orhe_delete_ciphertext(y_carry_out);

        if (carry_const) delete_gate_bootstrapping_ciphertext(carry_const);
    }

    ORHEProof signbit_proof;
    ORHECiphertext* x_sign = make_single_bit_ciphertext(&trace->diff->bits[trace->diff->nbits - 1], ks->tfhe_params);
    ORHECiphertext* y_sign = make_single_bit_ciphertext(trace->c_sgn, ks->tfhe_params);
    orhe_proof_prove_pbs(&signbit_proof, ks->pbs_pp, x_sign, y_sign);
    checkpoint_proofs.push_back(signbit_proof);
    orhe_delete_ciphertext(x_sign);
    orhe_delete_ciphertext(y_sign);

    const std::vector<uint8_t> backend_bytes = pack_checkpoint_proof_list(checkpoint_proofs);
    for (size_t i = 0; i < checkpoint_proofs.size(); ++i) {
        orhe_proof_clear(&checkpoint_proofs[i]);
    }

    {
        const std::vector<uint8_t> packed = pack_signext_compare_proof_blob(
            diff_bytes,
            trace_bytes,
            backend_bytes.data(),
            (uint64_t) backend_bytes.size()
        );
        out->blob = (uint8_t*) std::malloc(packed.size());
        std::memcpy(out->blob, packed.data(), packed.size());
        out->blob_len = (uint64_t) packed.size();
        out->family = ORHE_PROOF_FAMILY_SIGNEXT;
        out->owns_backend_buffer = 0;
    }
}

[[maybe_unused]] static int32_t orhe_proof_verify_signext_with_execution_trace(
    const ORHEProofPP* pp,
    const ORHEProofPP* pbs_pp,
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    const LweSample* c_sgn,
    const ORHEProof* proof,
    const ORHEKeySet* ks
) {
    const TFheGateBootstrappingParameterSet* params = ks->tfhe_params;
    if (!pp || !pbs_pp || !lhs || !rhs || !proof || proof->family != ORHE_PROOF_FAMILY_SIGNEXT) {
        return 0;
    }

    ORHESignExtCompareProofView view;
    if (!unpack_signext_compare_proof_blob(proof, &view)) return 0;
    if (!validate_compare_execution_trace_bytes(
            view.trace_ptr,
            view.trace_len,
            params,
            pp->bit_width)) {
        return 0;
    }
    std::vector<ORHEProofSlice> checkpoint_slices;
    if (!unpack_checkpoint_proof_list(view.backend_ptr, view.backend_len, &checkpoint_slices)) {
        return 0;
    }
    const size_t expected_proofs = (size_t) pp->bit_width * 7 + 1;
    if (checkpoint_slices.size() != expected_proofs) return 0;

    size_t diff_offset = 0;
    ORHECiphertext* diff = deserialize_ct_from_bytes(
        view.diff_ptr,
        (size_t) view.diff_len,
        &diff_offset,
        params,
        pp->bit_width
    );
    if (!diff || diff_offset != (size_t) view.diff_len) {
        if (diff) orhe_delete_ciphertext(diff);
        return 0;
    }
    ORHECompareExecutionTrace trace;
    if (!deserialize_compare_execution_trace_bytes(&trace, view.trace_ptr, view.trace_len, params, pp->bit_width)) {
        orhe_delete_ciphertext(diff);
        return 0;
    }

    size_t proof_idx = 0;
    int32_t ok = 1;
    for (int32_t i = 0; i < pp->bit_width && ok; ++i) {
        LweSample* carry_const = NULL;
        const LweSample* carry_in = (i == 0) ? NULL : &trace.carry_out_bits->bits[i - 1];
        if (i == 0) {
            carry_const = new_gate_bootstrapping_ciphertext(params);
            bootsCONSTANT(carry_const, 1, &ks->data_sk->cloud);
            carry_in = carry_const;
        }

        ORHECiphertext* b_not_expected = make_single_bit_ciphertext(&rhs->bits[i], params);
        bootsNOT(&b_not_expected->bits[0], &rhs->bits[i], &ks->data_sk->cloud);
        if (!orhe_lwe_equal(&b_not_expected->bits[0], &trace.b_not_bits->bits[i], params->in_out_params)) {
            orhe_delete_ciphertext(b_not_expected);
            if (carry_const) delete_gate_bootstrapping_ciphertext(carry_const);
            ok = 0;
            break;
        }
        orhe_delete_ciphertext(b_not_expected);

        auto verify_step = [&](ORHECiphertext* x_in, ORHECiphertext* y_out) -> int32_t {
            ORHEProof gate_proof;
            gate_proof.family = ORHE_PROOF_FAMILY_PBS;
            gate_proof.blob = (uint8_t*) checkpoint_slices[proof_idx].ptr;
            gate_proof.blob_len = checkpoint_slices[proof_idx].len;
            gate_proof.owns_backend_buffer = 0;
            ++proof_idx;
            int32_t step_ok = orhe_proof_verify_pbs(pbs_pp, x_in, y_out, &gate_proof);
            orhe_delete_ciphertext(x_in);
            orhe_delete_ciphertext(y_out);
            return step_ok;
        };

        ok = ok && verify_step(
            make_two_bit_ciphertext(&lhs->bits[i], &trace.b_not_bits->bits[i], params),
            make_single_bit_ciphertext(&trace.xor_ab_bits->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&trace.xor_ab_bits->bits[i], carry_in, params),
            make_single_bit_ciphertext(&diff->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&lhs->bits[i], &trace.b_not_bits->bits[i], params),
            make_single_bit_ciphertext(&trace.and_ab_bits->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&lhs->bits[i], carry_in, params),
            make_single_bit_ciphertext(&trace.and_a_cin_bits->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&trace.b_not_bits->bits[i], carry_in, params),
            make_single_bit_ciphertext(&trace.and_b_cin_bits->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&trace.and_ab_bits->bits[i], &trace.and_a_cin_bits->bits[i], params),
            make_single_bit_ciphertext(&trace.carry_or_bits->bits[i], params)
        );
        ok = ok && verify_step(
            make_two_bit_ciphertext(&trace.carry_or_bits->bits[i], &trace.and_b_cin_bits->bits[i], params),
            make_single_bit_ciphertext(&trace.carry_out_bits->bits[i], params)
        );

        if (carry_const) delete_gate_bootstrapping_ciphertext(carry_const);
    }
    if (ok) {
        ORHEProof sign_proof;
        sign_proof.family = ORHE_PROOF_FAMILY_PBS;
        sign_proof.blob = (uint8_t*) checkpoint_slices[proof_idx].ptr;
        sign_proof.blob_len = checkpoint_slices[proof_idx].len;
        sign_proof.owns_backend_buffer = 0;
        ORHECiphertext* x_sign = make_single_bit_ciphertext(&diff->bits[diff->nbits - 1], params);
        ORHECiphertext* y_sign = make_single_bit_ciphertext(c_sgn, params);
        ok = orhe_proof_verify_pbs(pbs_pp, x_sign, y_sign, &sign_proof);
        orhe_delete_ciphertext(x_sign);
        orhe_delete_ciphertext(y_sign);
    }

    compare_trace_delete(&trace);
    orhe_delete_ciphertext(diff);
    return ok;
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
    tr->sub_checkpoints = NULL;
    tr->nsub_checkpoints = 0;
    tr->cap_sub_checkpoints = 0;
    tr->wire_snapshots = NULL;
    tr->nwire_snapshots = 0;
    tr->cap_wire_snapshots = 0;
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
    for (int32_t i = 0; i < tr->nsub_checkpoints; ++i) {
        orhe_proof_clear(&tr->sub_checkpoints[i].proof);
    }

    for (int32_t i = 0; i < tr->nwire_snapshots; ++i) {
        if (tr->wire_snapshots[i]) orhe_delete_ciphertext(tr->wire_snapshots[i]);
    }

    std::free(tr->ops);
    std::free(tr->checkpoints);
    std::free(tr->sub_checkpoints);
    std::free(tr->wire_snapshots);
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

static void trace_ensure_sub_checkpoints(ORHECircuitTrace* tr) {
    if (tr->nsub_checkpoints < tr->cap_sub_checkpoints) return;
    int32_t newcap = (tr->cap_sub_checkpoints == 0) ? 4 : (2 * tr->cap_sub_checkpoints);
    ORHESubCheckpoint* fresh = (ORHESubCheckpoint*) std::malloc(sizeof(ORHESubCheckpoint) * newcap);
    for (int32_t i = 0; i < tr->nsub_checkpoints; ++i) fresh[i] = tr->sub_checkpoints[i];
    std::free(tr->sub_checkpoints);
    tr->sub_checkpoints = fresh;
    tr->cap_sub_checkpoints = newcap;
}

static void trace_ensure_wire_snapshots(ORHECircuitTrace* tr, int32_t wire) {
    if (wire < tr->cap_wire_snapshots) return;
    int32_t newcap = (tr->cap_wire_snapshots == 0) ? 8 : tr->cap_wire_snapshots;
    while (newcap <= wire) newcap *= 2;
    ORHECiphertext** fresh = (ORHECiphertext**) std::malloc(sizeof(ORHECiphertext*) * newcap);
    for (int32_t i = 0; i < newcap; ++i) fresh[i] = NULL;
    for (int32_t i = 0; i < tr->cap_wire_snapshots; ++i) fresh[i] = tr->wire_snapshots[i];
    std::free(tr->wire_snapshots);
    tr->wire_snapshots = fresh;
    tr->cap_wire_snapshots = newcap;
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

int32_t orhe_trace_append_sub_checkpoint(
    ORHECircuitTrace* tr,
    const ORHEProof* proof
) {
    trace_ensure_sub_checkpoints(tr);
    orhe_proof_copy(&tr->sub_checkpoints[tr->nsub_checkpoints].proof, proof);
    tr->nsub_checkpoints += 1;
    return 1;
}

int32_t orhe_trace_record_wire(
    ORHECircuitTrace* tr,
    int32_t wire,
    const ORHECiphertext* value
) {
    if (!tr || !value || wire < 0) return 0;
    trace_ensure_wire_snapshots(tr, wire);
    if (tr->wire_snapshots[wire]) {
        orhe_delete_ciphertext(tr->wire_snapshots[wire]);
        tr->wire_snapshots[wire] = NULL;
    }
    tr->wire_snapshots[wire] = orhe_clone_ciphertext(value);
    if (wire + 1 > tr->nwire_snapshots) tr->nwire_snapshots = wire + 1;
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
    orhe_set_register_derived_error("ok");
    if (orhe_lookup(H, h_new) != NULL) {
        orhe_set_register_derived_error("duplicate_handle");
        return 0;
    }
    if (!tr) {
        orhe_set_register_derived_error("missing_trace");
        return 0;
    }
    if (nsrc <= 0) {
        orhe_set_register_derived_error("derived_registration_requires_source_handles");
        return 0;
    }

    int32_t nwires = max_wire_index(tr) + 1;
    if (nwires <= 0) {
        orhe_set_register_derived_error("invalid_trace_wiring");
        return 0;
    }

    ORHECiphertext** wires = (ORHECiphertext**) std::malloc(sizeof(ORHECiphertext*) * nwires);
    for (int32_t i = 0; i < nwires; ++i) wires[i] = NULL;

    for (int32_t i = 0; i < nsrc; ++i) {
        const ORHEHandleEntry* e = orhe_lookup(H, src_handles[i]);
        if (!e) {
            orhe_set_register_derived_error("missing_source_handle");
            std::free(wires);
            return 0;
        }
        wires[i] = orhe_clone_ciphertext(e->ct);
    }

    int32_t checkpoint_cursor = 0;
    int32_t sub_checkpoint_cursor = 0;
    auto get_snapshot = [&](int32_t wire) -> const ORHECiphertext* {
        if (!tr->wire_snapshots) return NULL;
        if (wire < 0 || wire >= tr->nwire_snapshots) return NULL;
        return tr->wire_snapshots[wire];
    };
    auto finalize_wire = [&](int32_t dst_wire, ORHECiphertext* expected, const ORHECiphertext* snapshot, const char* mismatch_reason) -> int32_t {
        if (snapshot && !orhe_ct_equal(expected, snapshot)) {
            orhe_set_register_derived_error(mismatch_reason);
            orhe_delete_ciphertext(expected);
            return 0;
        }
        wires[dst_wire] = expected;
        return 1;
    };

    for (int32_t i = 0; i < tr->nops; ++i) {
        const ORHETraceOp* op = &tr->ops[i];
        const ORHECiphertext* snapshot = get_snapshot(op->dst_wire);

        switch (op->kind) {
            case ORHE_TRACE_OP_INPUT:
                if (op->dst_wire < 0 || op->dst_wire >= nwires || !wires[op->dst_wire]) {
                    orhe_set_register_derived_error("missing_input_wire_value");
                    goto fail;
                }
                if (snapshot && !orhe_ct_equal(snapshot, wires[op->dst_wire])) {
                    orhe_set_register_derived_error("input_snapshot_mismatch");
                    goto fail;
                }
                break;

            case ORHE_TRACE_OP_COPY:
                if (!wires[op->src0_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_copy(expected, wires[op->src0_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "copy_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_CONST:
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    const uint32_t value = (uint32_t) op->aux_value;
                    for (int32_t bit = 0; bit < tr->bit_width; ++bit) {
                        const int32_t value_bit = ((value >> bit) & 1u) ? 1 : 0;
                        bootsCONSTANT(&expected->bits[bit], value_bit, &ks->data_sk->cloud);
                    }
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "const_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_NOT:
                if (!wires[op->src0_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_not(expected, wires[op->src0_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "not_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_XOR:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_xor(expected, wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "xor_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_AND:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_and(expected, wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "and_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_OR:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_or(expected, wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "or_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_MUX:
                if (!wires[op->src0_wire] || !wires[op->src1_wire] || !wires[op->src2_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_mux(
                        expected,
                        &wires[op->src0_wire]->bits[0],
                        wires[op->src1_wire],
                        wires[op->src2_wire],
                        &ks->data_sk->cloud
                    );
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "mux_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_ADD:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_add(expected, wires[op->src0_wire], wires[op->src1_wire], &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "add_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_SUB:
                if (!wires[op->src0_wire] || !wires[op->src1_wire]) goto fail;
                {
                    if (sub_checkpoint_cursor >= tr->nsub_checkpoints) {
                        orhe_set_register_derived_error("missing_sub_checkpoint");
                        goto fail;
                    }
                    if (!snapshot) {
                        orhe_set_register_derived_error("missing_sub_snapshot");
                        goto fail;
                    }
                    const ORHESubCheckpoint* cp = &tr->sub_checkpoints[sub_checkpoint_cursor++];
                    if (!orhe_proof_verify_sub_partial(
                            ks->sub_pp,
                            wires[op->src0_wire],
                            wires[op->src1_wire],
                            snapshot,
                            &cp->proof,
                            ks)) {
                        orhe_set_register_derived_error("sub_checkpoint_proof_failed");
                        goto fail;
                    }
                    wires[op->dst_wire] = orhe_clone_ciphertext(snapshot);
                }
                break;

            case ORHE_TRACE_OP_SHR:
                if (!wires[op->src0_wire]) goto fail;
                if (op->aux_value < 0 || op->aux_value > tr->bit_width) {
                    orhe_set_register_derived_error("invalid_shift_amount");
                    goto fail;
                }
                {
                    ORHECiphertext* expected = orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    orhe_shr(expected, wires[op->src0_wire], op->aux_value, &ks->data_sk->cloud);
                    if (!finalize_wire(op->dst_wire, expected, snapshot, "shr_snapshot_mismatch")) goto fail;
                }
                break;

            case ORHE_TRACE_OP_PBS:
                if (checkpoint_cursor >= tr->ncheckpoints) {
                    orhe_set_register_derived_error("missing_pbs_checkpoint");
                    goto fail;
                }
                if (!wires[op->src0_wire]) goto fail;
                {
                    const int32_t semantic_pbs =
                        orhe_pbs_semantic_relation_supported(op->aux_value) ? 1 : 0;
                    const ORHEPBSCheckpoint* cp = &tr->checkpoints[checkpoint_cursor++];
                    const ORHEProofPP* verify_pp = semantic_pbs ? ks->reg_pbs_pp : ks->pbs_pp;
                    ORHECiphertext* expected = semantic_pbs ?
                        orhe_clone_ciphertext(cp->y_out) :
                        orhe_new_ciphertext(tr->bit_width, ks->tfhe_params);
                    if (!orhe_ct_equal(wires[op->src0_wire], cp->x_in)) {
                        orhe_set_register_derived_error("pbs_input_mismatch");
                        orhe_delete_ciphertext(expected);
                        goto fail;
                    }
                    if (!orhe_proof_verify_pbs_relation(
                            verify_pp,
                            op->aux_value,
                            cp->x_in,
                            cp->y_out,
                            &cp->proof,
                            ks)) {
                        orhe_set_register_derived_error("pbs_checkpoint_proof_failed");
                        orhe_delete_ciphertext(expected);
                        goto fail;
                    }
                    if (!semantic_pbs) {
                        if (!orhe_eval_allowed_pbs_relation(expected, cp->x_in, op->aux_value, ks)) {
                            orhe_set_register_derived_error("unsupported_pbs_relation");
                            orhe_delete_ciphertext(expected);
                            goto fail;
                        }
                        if (!orhe_ct_equal(expected, cp->y_out)) {
                            orhe_set_register_derived_error("pbs_semantic_mismatch");
                            orhe_delete_ciphertext(expected);
                            goto fail;
                        }
                    }
                    if (snapshot && !orhe_ct_equal(expected, snapshot)) {
                        orhe_set_register_derived_error("pbs_snapshot_mismatch");
                        orhe_delete_ciphertext(expected);
                        goto fail;
                    }
                    wires[op->dst_wire] = orhe_clone_ciphertext(cp->y_out);
                    orhe_delete_ciphertext(expected);
                }
                break;

            default:
                orhe_set_register_derived_error("unsupported_trace_op");
                goto fail;
        }
    }

    if (checkpoint_cursor != tr->ncheckpoints) {
        orhe_set_register_derived_error("unused_pbs_checkpoint");
        goto fail;
    }
    if (sub_checkpoint_cursor != tr->nsub_checkpoints) {
        orhe_set_register_derived_error("unused_sub_checkpoint");
        goto fail;
    }

    if (tr->final_wire < 0 || tr->final_wire >= nwires) {
        orhe_set_register_derived_error("invalid_final_wire");
        goto fail;
    }
    if (!wires[tr->final_wire] &&
        tr->nops > 0 &&
        tr->ncheckpoints > 0 &&
        tr->ops[tr->nops - 1].kind == ORHE_TRACE_OP_PBS &&
        tr->ops[tr->nops - 1].dst_wire == tr->final_wire &&
        checkpoint_cursor == tr->ncheckpoints) {
        wires[tr->final_wire] = orhe_clone_ciphertext(tr->checkpoints[tr->ncheckpoints - 1].y_out);
    }
    if (!wires[tr->final_wire]) {
        orhe_set_register_derived_error("missing_final_wire_value");
        goto fail;
    }
    if (!orhe_ct_equal(wires[tr->final_wire], c_claimed)) {
        orhe_set_register_derived_error("claimed_ciphertext_mismatch");
        goto fail;
    }

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
    ORHEProof* pi_out,
    const ORHEKeySet* ks
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return 0;

    ORHECiphertext* diff = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHECompareExecutionTrace trace;
    ORHEProof signext_pi;
    ORHEProof ks_pi;
    compare_trace_init(&trace);
    compare_trace_prepare(&trace, ks->params.bit_width, ks->tfhe_params, ks->cmp_sk->params);
    std::memset(&signext_pi, 0, sizeof(signext_pi));
    std::memset(&ks_pi, 0, sizeof(ks_pi));

    orhe_compare_tfhe_path_with_metrics(e1->ct, e2->ct, diff, c_sgn_out, u_out, ks, NULL, &trace);
    orhe_proof_prove_signext_from_execution_trace(&signext_pi, ks->signext_pp, e1->ct, e2->ct, &trace, ks);
    orhe_proof_prove_ks(&ks_pi, ks->ks_pp, c_sgn_out, u_out, ks->tfhe_params);
    if (signext_pi.family == ORHE_PROOF_FAMILY_SIGNEXT &&
        ks_pi.family == ORHE_PROOF_FAMILY_KS) {
        const std::vector<uint8_t> packed = pack_compare_proof_bundle(&signext_pi, &ks_pi);
        pi_out->family = ORHE_PROOF_FAMILY_SIGNEXT;
        pi_out->blob = (uint8_t*) std::malloc(packed.size());
        std::memcpy(pi_out->blob, packed.data(), packed.size());
        pi_out->blob_len = (uint64_t) packed.size();
        pi_out->owns_backend_buffer = 0;
    } else {
        pi_out->family = ORHE_PROOF_FAMILY_NONE;
        pi_out->blob = NULL;
        pi_out->blob_len = 0;
        pi_out->owns_backend_buffer = 0;
    }
    orhe_proof_clear(&signext_pi);
    orhe_proof_clear(&ks_pi);
    orhe_delete_ciphertext(diff);
    compare_trace_delete(&trace);
    return pi_out && pi_out->family == ORHE_PROOF_FAMILY_SIGNEXT ? 1 : 0;
}

int32_t orhe_gate_compare_verified(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi,
    const ORHEKeySet* ks
) {
    static bool dumped_once = false;
    ORHECompareProofBundleView bundle;
    ORHEProof signext_pi;
    ORHEProof ks_pi;
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return -1;
    if (!unpack_compare_proof_bundle(pi, &bundle)) return -1;

    std::memset(&signext_pi, 0, sizeof(signext_pi));
    std::memset(&ks_pi, 0, sizeof(ks_pi));
    signext_pi.family = ORHE_PROOF_FAMILY_SIGNEXT;
    signext_pi.blob = (uint8_t*) bundle.signext_ptr;
    signext_pi.blob_len = bundle.signext_len;
    signext_pi.owns_backend_buffer = 0;
    ks_pi.family = ORHE_PROOF_FAMILY_KS;
    ks_pi.blob = (uint8_t*) bundle.ks_ptr;
    ks_pi.blob_len = bundle.ks_len;
    ks_pi.owns_backend_buffer = 0;
    int32_t proof_ok =
        orhe_proof_verify_signext_with_execution_trace(ks->signext_pp, ks->pbs_pp, e1->ct, e2->ct, c_sgn, &signext_pi, ks);
    if (orhe_debug_compare_enabled() && !dumped_once) {
        std::fprintf(stderr, "[c++][compare-debug] signext proof verification result=%d\n", proof_ok);
    }
    if (!proof_ok) {
        return -1;
    }

    if (!orhe_proof_verify_ks(ks->ks_pp, c_sgn, u, &ks_pi, ks->tfhe_params)) {
        return -1;
    }

    Torus32 phase = lwePhase(u, ks->cmp_sk);
    int32_t sigma = (phase > 0) ? 1 : 0;

    if (orhe_debug_compare_enabled() && !dumped_once) {
        dumped_once = true;
        std::fprintf(
            stderr,
            "[c++][compare-debug] raw compare output: u->b=%d phase=%d sigma=%d\n",
            (int) u->b,
            (int) phase,
            sigma
        );
    }

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
    if (!orhe_insecure_debug_api_enabled()) return -1;
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
    uint64_t snapshot_bytes = 0;
    if (tr) {
        for (int32_t i = 0; i < tr->ncheckpoints; ++i) {
            proof_bytes += orhe_proof_size_bytes(&tr->checkpoints[i].proof);
        }
        for (int32_t i = 0; i < tr->nwire_snapshots; ++i) {
            if (tr->wire_snapshots[i]) snapshot_bytes += orhe_ciphertext_size_bytes(tr->wire_snapshots[i]);
        }
    }

    if (m) {
        m->register_derived_verifier_us += verify_us;
        m->verifier_us += verify_us;
        m->end_to_end_online_us += total_us;

        m->proof_size_bytes += proof_bytes;
        m->ciphertext_size_bytes += orhe_ciphertext_size_bytes(c_claimed) + snapshot_bytes;
        m->metadata_size_bytes += sizeof(uint64_t) + 32 + sizeof(uint8_t);

        // online communication for derived registration:
        // handles + claimed ciphertext + checkpoint proofs + wire snapshots
        m->total_online_comm_bytes +=
            ((uint64_t) nsrc + 1) * sizeof(uint64_t) +
            orhe_ciphertext_size_bytes(c_claimed) +
            proof_bytes +
            snapshot_bytes;

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
    ORHEProof* pi_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return 0;
    ORHECiphertext* diff = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHECompareExecutionTrace trace;
    ORHEProof signext_pi;
    ORHEProof ks_pi;
    compare_trace_init(&trace);
    compare_trace_prepare(&trace, ks->params.bit_width, ks->tfhe_params, ks->cmp_sk->params);
    std::memset(&signext_pi, 0, sizeof(signext_pi));
    std::memset(&ks_pi, 0, sizeof(ks_pi));

    ORHETimer total_t, prove_t;
    orhe_timer_start(&total_t);
    orhe_compare_tfhe_path_with_metrics(e1->ct, e2->ct, diff, c_sgn_out, u_out, ks, m, &trace);

    orhe_timer_start(&prove_t);
    orhe_proof_prove_signext_from_execution_trace(&signext_pi, ks->signext_pp, e1->ct, e2->ct, &trace, ks);
    orhe_proof_prove_ks(&ks_pi, ks->ks_pp, c_sgn_out, u_out, ks->tfhe_params);
    if (signext_pi.family == ORHE_PROOF_FAMILY_SIGNEXT &&
        ks_pi.family == ORHE_PROOF_FAMILY_KS) {
        const std::vector<uint8_t> packed = pack_compare_proof_bundle(&signext_pi, &ks_pi);
        pi_out->family = ORHE_PROOF_FAMILY_SIGNEXT;
        pi_out->blob = (uint8_t*) std::malloc(packed.size());
        std::memcpy(pi_out->blob, packed.data(), packed.size());
        pi_out->blob_len = (uint64_t) packed.size();
        pi_out->owns_backend_buffer = 0;
    } else {
        pi_out->family = ORHE_PROOF_FAMILY_NONE;
        pi_out->blob = NULL;
        pi_out->blob_len = 0;
        pi_out->owns_backend_buffer = 0;
    }
    orhe_proof_clear(&signext_pi);
    orhe_proof_clear(&ks_pi);
    uint64_t prove_us = orhe_timer_elapsed_us(&prove_t);

    uint64_t total_us = orhe_timer_elapsed_us(&total_t);

    if (m) {
        m->prover_us += prove_us;
        m->compare_prover_us += prove_us;

        m->end_to_end_online_us += total_us;

        m->proof_size_bytes += orhe_proof_size_bytes(pi_out);

        m->ciphertext_size_bytes +=
            orhe_ciphertext_size_bytes(diff) +
            orhe_lwe_size_bytes(c_sgn_out, ks->tfhe_params->in_out_params) +
            orhe_lwe_size_bytes(u_out, ks->cmp_sk->params);

        m->metadata_size_bytes += 2 * sizeof(uint64_t);

        // server sends handles + c_sgn + u + bundled compare proof
        m->total_online_comm_bytes +=
            2 * sizeof(uint64_t) +
            orhe_lwe_size_bytes(c_sgn_out, ks->tfhe_params->in_out_params) +
            orhe_lwe_size_bytes(u_out, ks->cmp_sk->params) +
            orhe_proof_size_bytes(pi_out);

        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    orhe_delete_ciphertext(diff);
    compare_trace_delete(&trace);
    return pi_out && pi_out->family == ORHE_PROOF_FAMILY_SIGNEXT ? 1 : 0;
}

int32_t orhe_compare_plain_with_metrics(
    const ORHECiphertext* lhs,
    const ORHECiphertext* rhs,
    LweSample* c_sgn_out,
    LweSample* u_out,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    if (!orhe_insecure_debug_api_enabled()) return -1;
    ORHECiphertext* d = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer total_t;
    orhe_timer_start(&total_t);
    orhe_compare_tfhe_path_with_metrics(lhs, rhs, d, c_sgn_out, u_out, ks, m, NULL);

    const Torus32 phase = lwePhase(u_out, ks->cmp_sk);
    const int32_t sigma = (phase > 0) ? 1 : 0;

    if (m) {
        m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);
    }

    orhe_delete_ciphertext(d);
    return sigma;
}

int32_t orhe_gate_compare_verified_with_metrics(
    uint64_t h1,
    uint64_t h2,
    const ORHEHandleTable* H,
    const LweSample* c_sgn,
    const LweSample* u,
    const ORHEProof* pi,
    const ORHEKeySet* ks,
    ORHEMetrics* m
) {
    static bool dumped_once = false;
    ORHECompareProofBundleView bundle;
    ORHEProof signext_pi;
    ORHEProof ks_pi;
    const ORHEHandleEntry* e1 = orhe_lookup(H, h1);
    const ORHEHandleEntry* e2 = orhe_lookup(H, h2);
    if (!e1 || !e2) return -1;
    if (!unpack_compare_proof_bundle(pi, &bundle)) return -1;
    std::memset(&signext_pi, 0, sizeof(signext_pi));
    std::memset(&ks_pi, 0, sizeof(ks_pi));
    signext_pi.family = ORHE_PROOF_FAMILY_SIGNEXT;
    signext_pi.blob = (uint8_t*) bundle.signext_ptr;
    signext_pi.blob_len = bundle.signext_len;
    signext_pi.owns_backend_buffer = 0;
    ks_pi.family = ORHE_PROOF_FAMILY_KS;
    ks_pi.blob = (uint8_t*) bundle.ks_ptr;
    ks_pi.blob_len = bundle.ks_len;
    ks_pi.owns_backend_buffer = 0;

    ORHETimer total_t, verify_t;
    orhe_timer_start(&total_t);

    orhe_timer_start(&verify_t);
    int32_t proof_ok =
        orhe_proof_verify_signext_with_execution_trace(ks->signext_pp, ks->pbs_pp, e1->ct, e2->ct, c_sgn, &signext_pi, ks) &&
        orhe_proof_verify_ks(ks->ks_pp, c_sgn, u, &ks_pi, ks->tfhe_params);
    const uint64_t proof_verify_us = orhe_timer_elapsed_us(&verify_t);
    if (orhe_debug_compare_enabled() && !dumped_once) {
        std::fprintf(stderr, "[c++][compare-debug] signext proof verification result=%d\n", proof_ok);
    }
    if (!proof_ok) {
        if (m) {
            m->verifier_us += proof_verify_us;
            m->compare_verifier_us += proof_verify_us;
            m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);
        }
        return -1;
    }

    Torus32 phase = lwePhase(u, ks->cmp_sk);
    int32_t sigma = (phase > 0) ? 1 : 0;

    if (orhe_debug_compare_enabled() && !dumped_once) {
        dumped_once = true;
        std::fprintf(
            stderr,
            "[c++][compare-debug] raw compare output: u->b=%d phase=%d sigma=%d\n",
            (int) u->b,
            (int) phase,
            sigma
        );
    }

    if (m) {
        m->verifier_us += proof_verify_us;
        m->compare_verifier_us += proof_verify_us;
        m->end_to_end_online_us += orhe_timer_elapsed_us(&total_t);

        m->server_state_bytes = orhe_handle_table_size_bytes(H);
        m->gate_state_bytes = orhe_gate_state_size_bytes(ks);
    }

    return sigma;
}
