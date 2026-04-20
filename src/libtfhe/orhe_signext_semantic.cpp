#include "orhe.h"
#include "orhe_plonky2_backend.h"
#include "tfhe.h"

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

static const uint32_t ORHE_SIGNEXT_SEMANTIC_VERSION = 3u;
static const uint32_t ORHE_SIGNEXT_PROOF_MAGIC = 0x31505253u;  // "SRP1"
static const uint32_t ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3 = 1u;
static const uint32_t ORHE_SIGNEXT_PARTIAL_BACKEND_VERSION = 1u;

enum SemanticKind : uint16_t {
    SEM_KIND_CT = 1,
    SEM_KIND_LWE = 2,
    SEM_KIND_CTX = 3,
    SEM_KIND_STMT = 4,
    SEM_KIND_B1 = 5,
    SEM_KIND_B2 = 6,
    SEM_KIND_B3 = 7,
    SEM_KIND_B4 = 8,
    SEM_KIND_WIT = 9,
    SEM_KIND_TLWE = 10
};

struct BytesCursor {
    const uint8_t* ptr;
    uint64_t len;
    uint64_t off;
};

static void append_bytes(std::vector<uint8_t>& out, const void* ptr, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(ptr);
    out.insert(out.end(), p, p + len);
}

static void append_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back((uint8_t) (v & 0xffu));
    out.push_back((uint8_t) ((v >> 8) & 0xffu));
}

static void append_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back((uint8_t) ((v >> (8 * i)) & 0xffu));
}

static void append_i32(std::vector<uint8_t>& out, int32_t v) {
    append_u32(out, (uint32_t) v);
}

static void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back((uint8_t) ((v >> (8 * i)) & 0xffu));
}

static void append_f64_bits(std::vector<uint8_t>& out, double value) {
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    append_u64(out, bits);
}

static bool cursor_read(BytesCursor* cur, void* dst, uint64_t len) {
    if (!cur || cur->off > cur->len || len > cur->len - cur->off) return false;
    std::memcpy(dst, cur->ptr + cur->off, (size_t) len);
    cur->off += len;
    return true;
}

static bool cursor_read_u16(BytesCursor* cur, uint16_t* out) {
    uint8_t bytes[2];
    if (!cursor_read(cur, bytes, sizeof(bytes))) return false;
    *out = (uint16_t) bytes[0] | ((uint16_t) bytes[1] << 8);
    return true;
}

static bool cursor_read_u32(BytesCursor* cur, uint32_t* out) {
    uint8_t bytes[4];
    if (!cursor_read(cur, bytes, sizeof(bytes))) return false;
    *out = ((uint32_t) bytes[0]) |
           ((uint32_t) bytes[1] << 8) |
           ((uint32_t) bytes[2] << 16) |
           ((uint32_t) bytes[3] << 24);
    return true;
}

static bool cursor_read_i32(BytesCursor* cur, int32_t* out) {
    uint32_t v = 0;
    if (!cursor_read_u32(cur, &v)) return false;
    *out = (int32_t) v;
    return true;
}

static bool cursor_read_u64(BytesCursor* cur, uint64_t* out) {
    uint8_t bytes[8];
    if (!cursor_read(cur, bytes, sizeof(bytes))) return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t) bytes[i]) << (8 * i);
    *out = v;
    return true;
}

static bool cursor_read_f64_bits(BytesCursor* cur, double* out) {
    uint64_t bits = 0;
    if (!cursor_read_u64(cur, &bits)) return false;
    std::memcpy(out, &bits, sizeof(bits));
    return true;
}

static void append_envelope(std::vector<uint8_t>& out, SemanticKind kind) {
    append_bytes(out, "ORHE", 4);
    append_u16(out, (uint16_t) kind);
    append_u16(out, (uint16_t) ORHE_SIGNEXT_SEMANTIC_VERSION);
}

static bool cursor_expect_envelope(BytesCursor* cur, SemanticKind kind) {
    uint8_t magic[4];
    uint16_t got_kind = 0;
    uint16_t got_version = 0;
    if (!cursor_read(cur, magic, sizeof(magic))) return false;
    if (std::memcmp(magic, "ORHE", 4) != 0) return false;
    if (!cursor_read_u16(cur, &got_kind)) return false;
    if (!cursor_read_u16(cur, &got_version)) return false;
    return got_kind == (uint16_t) kind && got_version == ORHE_SIGNEXT_SEMANTIC_VERSION;
}

static bool orhe_bytes_assign(ORHEBytes* out, const std::vector<uint8_t>& bytes) {
    out->ptr = NULL;
    out->len = 0;
    if (bytes.empty()) return true;
    out->ptr = (uint8_t*) std::malloc(bytes.size());
    if (!out->ptr) return false;
    std::memcpy(out->ptr, bytes.data(), bytes.size());
    out->len = (uint64_t) bytes.size();
    return true;
}

static void digest_init(uint8_t out[32], uint8_t tag) {
    for (int i = 0; i < 32; ++i) {
        out[i] = (uint8_t) (0x41u + tag + 11 * i);
    }
}

static void digest_mix(uint8_t out[32], const void* ptr, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        out[i % 32] ^= (uint8_t) (p[i] + (uint8_t) i + 17u);
        out[(i * 5u) % 32] = (uint8_t) (out[(i * 5u) % 32] + p[i] + 23u);
        out[(i * 13u) % 32] ^= (uint8_t) (p[i] << (i & 1u));
    }
}

static void digest_bytes(uint8_t out[32], uint8_t tag, const std::vector<uint8_t>& bytes) {
    digest_init(out, tag);
    digest_mix(out, bytes.data(), bytes.size());
}

static bool lwe_equal(const LweSample* a, const LweSample* b, const LweParams* params) {
    if (!a || !b) return false;
    if (a->b != b->b) return false;
    if (a->current_variance != b->current_variance) return false;
    for (int32_t i = 0; i < params->n; ++i) {
        if (a->a[i] != b->a[i]) return false;
    }
    return true;
}

static bool tlwe_equal(const TLweSample* a, const TLweSample* b, const TLweParams* params) {
    if (!a || !b || !params) return false;
    if (a->current_variance != b->current_variance) return false;
    for (int32_t poly = 0; poly <= params->k; ++poly) {
        for (int32_t i = 0; i < params->N; ++i) {
            if (a->a[poly].coefsT[i] != b->a[poly].coefsT[i]) return false;
        }
    }
    return true;
}

static void serialize_lwe_vec(std::vector<uint8_t>& out, const LweSample* sample, const LweParams* params) {
    append_envelope(out, SEM_KIND_LWE);
    append_i32(out, params->n);
    for (int32_t i = 0; i < params->n; ++i) append_i32(out, sample->a[i]);
    append_i32(out, sample->b);
    append_f64_bits(out, sample->current_variance);
}

static bool serialize_lwe_bytes(ORHEBytes* out, const LweSample* sample, const LweParams* params) {
    std::vector<uint8_t> bytes;
    serialize_lwe_vec(bytes, sample, params);
    return orhe_bytes_assign(out, bytes);
}

static void serialize_tlwe_vec(std::vector<uint8_t>& out, const TLweSample* sample, const TLweParams* params) {
    append_envelope(out, SEM_KIND_TLWE);
    append_i32(out, params->N);
    append_i32(out, params->k);
    for (int32_t poly = 0; poly <= params->k; ++poly) {
        for (int32_t i = 0; i < params->N; ++i) append_i32(out, sample->a[poly].coefsT[i]);
    }
    append_f64_bits(out, sample->current_variance);
}

static bool serialize_tlwe_bytes(ORHEBytes* out, const TLweSample* sample, const TLweParams* params) {
    std::vector<uint8_t> bytes;
    serialize_tlwe_vec(bytes, sample, params);
    return orhe_bytes_assign(out, bytes);
}

static void serialize_ct_vec(std::vector<uint8_t>& out, const ORHECiphertext* ct) {
    append_envelope(out, SEM_KIND_CT);
    append_i32(out, ct->nbits);
    append_i32(out, ct->lwe_params->n);
    for (int32_t bit = 0; bit < ct->nbits; ++bit) {
        for (int32_t i = 0; i < ct->lwe_params->n; ++i) append_i32(out, ct->bits[bit].a[i]);
        append_i32(out, ct->bits[bit].b);
        append_f64_bits(out, ct->bits[bit].current_variance);
    }
}

static bool serialize_ct_bytes(ORHEBytes* out, const ORHECiphertext* ct) {
    std::vector<uint8_t> bytes;
    serialize_ct_vec(bytes, ct);
    return orhe_bytes_assign(out, bytes);
}

static void append_nested_bytes(std::vector<uint8_t>& out, const ORHEBytes* bytes) {
    append_u64(out, bytes ? bytes->len : 0);
    if (bytes && bytes->len > 0) append_bytes(out, bytes->ptr, (size_t) bytes->len);
}

static bool cursor_read_nested_bytes(BytesCursor* cur, ORHEBytes* out) {
    uint64_t len = 0;
    if (!cursor_read_u64(cur, &len)) return false;
    out->ptr = NULL;
    out->len = 0;
    if (len == 0) return true;
    out->ptr = (uint8_t*) std::malloc((size_t) len);
    if (!out->ptr) return false;
    out->len = len;
    if (!cursor_read(cur, out->ptr, len)) {
        std::free(out->ptr);
        out->ptr = NULL;
        out->len = 0;
        return false;
    }
    return true;
}

static bool deserialize_lwe_alloc(
    const ORHEBytes* bytes,
    const LweParams* expected_params,
    LweSample** out
) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    int32_t n = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_LWE)) return false;
    if (!cursor_read_i32(&cur, &n)) return false;
    if (!expected_params || n != expected_params->n) return false;

    LweSample* sample = new_LweSample(expected_params);
    for (int32_t i = 0; i < n; ++i) {
        if (!cursor_read_i32(&cur, &sample->a[i])) {
            delete_LweSample(sample);
            return false;
        }
    }
    if (!cursor_read_i32(&cur, &sample->b) ||
        !cursor_read_f64_bits(&cur, &sample->current_variance) ||
        cur.off != cur.len) {
        delete_LweSample(sample);
        return false;
    }
    *out = sample;
    return true;
}

static bool deserialize_tlwe_alloc(
    const ORHEBytes* bytes,
    const TLweParams* expected_params,
    TLweSample** out
) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    int32_t N = 0;
    int32_t k = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_TLWE)) return false;
    if (!cursor_read_i32(&cur, &N) || !cursor_read_i32(&cur, &k)) return false;
    if (!expected_params || N != expected_params->N || k != expected_params->k) return false;

    TLweSample* sample = new_TLweSample(expected_params);
    for (int32_t poly = 0; poly <= k; ++poly) {
        for (int32_t i = 0; i < N; ++i) {
            if (!cursor_read_i32(&cur, &sample->a[poly].coefsT[i])) {
                delete_TLweSample(sample);
                return false;
            }
        }
    }
    if (!cursor_read_f64_bits(&cur, &sample->current_variance) || cur.off != cur.len) {
        delete_TLweSample(sample);
        return false;
    }
    *out = sample;
    return true;
}

static bool deserialize_ct_alloc(
    const ORHEBytes* bytes,
    const TFheGateBootstrappingParameterSet* params,
    ORHECiphertext** out
) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    int32_t nbits = 0;
    int32_t n = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_CT)) return false;
    if (!cursor_read_i32(&cur, &nbits) || !cursor_read_i32(&cur, &n)) return false;
    if (!params || n != params->in_out_params->n) return false;

    ORHECiphertext* ct = orhe_new_ciphertext(nbits, params);
    for (int32_t bit = 0; bit < nbits; ++bit) {
        for (int32_t i = 0; i < n; ++i) {
            if (!cursor_read_i32(&cur, &ct->bits[bit].a[i])) {
                orhe_delete_ciphertext(ct);
                return false;
            }
        }
        if (!cursor_read_i32(&cur, &ct->bits[bit].b) ||
            !cursor_read_f64_bits(&cur, &ct->bits[bit].current_variance)) {
            orhe_delete_ciphertext(ct);
            return false;
        }
    }
    if (cur.off != cur.len) {
        orhe_delete_ciphertext(ct);
        return false;
    }
    *out = ct;
    return true;
}

struct ParsedLweBytes {
    int32_t n;
    std::vector<int32_t> a;
    int32_t b;
    double current_variance;
};

struct ParsedTlweBytes {
    int32_t N;
    int32_t k;
    std::vector<int32_t> polys;
    double current_variance;
};

enum PartialSemanticKind : uint32_t {
    PARTIAL_SEM_STMT = 1,
    PARTIAL_SEM_WIT = 2
};

static void append_partial_envelope(std::vector<uint8_t>& out, PartialSemanticKind kind) {
    append_bytes(out, "ORPS", 4);
    append_u32(out, ORHE_SIGNEXT_PARTIAL_BACKEND_VERSION);
    append_u32(out, (uint32_t) kind);
}

static bool parse_lwe_bytes_generic(const ORHEBytes* bytes, ParsedLweBytes* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    int32_t n = 0;
    if (!out || !cursor_expect_envelope(&cur, SEM_KIND_LWE) || !cursor_read_i32(&cur, &n) || n <= 0) return false;
    out->n = n;
    out->a.assign((size_t) n, 0);
    for (int32_t i = 0; i < n; ++i) {
        if (!cursor_read_i32(&cur, &out->a[(size_t) i])) return false;
    }
    if (!cursor_read_i32(&cur, &out->b) ||
        !cursor_read_f64_bits(&cur, &out->current_variance) ||
        cur.off != cur.len) {
        return false;
    }
    return true;
}

static bool parse_tlwe_bytes_generic(const ORHEBytes* bytes, ParsedTlweBytes* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    int32_t N = 0;
    int32_t k = 0;
    if (!out || !cursor_expect_envelope(&cur, SEM_KIND_TLWE) || !cursor_read_i32(&cur, &N) || !cursor_read_i32(&cur, &k)) {
        return false;
    }
    if (N <= 0 || k < 0) return false;
    out->N = N;
    out->k = k;
    out->polys.assign((size_t) (k + 1) * (size_t) N, 0);
    for (int32_t poly = 0; poly <= k; ++poly) {
        for (int32_t i = 0; i < N; ++i) {
            if (!cursor_read_i32(&cur, &out->polys[(size_t) poly * (size_t) N + (size_t) i])) return false;
        }
    }
    if (!cursor_read_f64_bits(&cur, &out->current_variance) || cur.off != cur.len) return false;
    return true;
}

static bool compute_signext_b1_shape(
    int32_t* boundary_out,
    uint32_t* first_positive_out,
    const ParsedLweBytes* pbs_input,
    int32_t accum_n
) {
    if (!boundary_out || !first_positive_out || !pbs_input || accum_n <= 0) return false;
    const int32_t two_n = 2 * accum_n;
    const int32_t barb = modSwitchFromTorus32((Torus32) pbs_input->b, two_n);

    if (barb == 0) {
        *boundary_out = accum_n;
        *first_positive_out = 1u;
        return true;
    }

    if (barb <= accum_n) {
        *boundary_out = accum_n - barb;
        *first_positive_out = 1u;
        return true;
    }

    *boundary_out = two_n - barb;
    *first_positive_out = 0u;
    return true;
}

static bool has_int32_min_negation_hazard(const ParsedTlweBytes* blind_rot) {
    if (!blind_rot || blind_rot->k != 1 || blind_rot->N <= 0) return true;
    const size_t poly0 = 0;
    for (int32_t j = 1; j < blind_rot->N; ++j) {
        if (blind_rot->polys[poly0 + (size_t) blind_rot->N - (size_t) j] == INT32_MIN) return true;
    }
    return false;
}

static bool build_partial_backend_statement_vec(std::vector<uint8_t>& out, const ORHESignExtPublicStatement* stmt) {
    if (!stmt) return false;
    append_partial_envelope(out, PARTIAL_SEM_STMT);
    append_u32(out, stmt->relation_id);
    append_bytes(out, &stmt->tfhe_ctx_id, sizeof(stmt->tfhe_ctx_id));
    append_nested_bytes(out, &stmt->d_ser);
    append_nested_bytes(out, &stmt->pbs_input_ser);
    append_nested_bytes(out, &stmt->c_sgn_ser);
    return true;
}

static bool build_partial_backend_witness_vec(
    std::vector<uint8_t>& out,
    const ORHESignExtWitness* wit
) {
    ParsedLweBytes pbs_input;
    ParsedLweBytes pre_ks;
    ParsedTlweBytes accum_init;
    ParsedTlweBytes blind_rot;
    int32_t boundary = 0;
    uint32_t first_positive = 0;

    if (!wit ||
        !parse_lwe_bytes_generic(&wit->pbs_input_ser, &pbs_input) ||
        !parse_tlwe_bytes_generic(&wit->b1.accum_init_tlwe_ser, &accum_init) ||
        !parse_tlwe_bytes_generic(&wit->b3.blind_rot_accum_tlwe_ser, &blind_rot) ||
        !parse_lwe_bytes_generic(&wit->b3.pre_ks_lwe_ser, &pre_ks)) {
        return false;
    }

    if (accum_init.k != 1 || blind_rot.k != 1 || blind_rot.N != accum_init.N || pre_ks.n != blind_rot.N) return false;
    if (!compute_signext_b1_shape(&boundary, &first_positive, &pbs_input, accum_init.N)) return false;
    if (has_int32_min_negation_hazard(&blind_rot)) return false;

    append_partial_envelope(out, PARTIAL_SEM_WIT);
    append_u32(out, (uint32_t) accum_init.N);
    append_u32(out, (uint32_t) boundary);
    append_u32(out, first_positive);
    for (int32_t i = 0; i < accum_init.N; ++i) append_i32(out, accum_init.polys[(size_t) i]);
    for (int32_t i = 0; i < accum_init.N; ++i) append_i32(out, accum_init.polys[(size_t) accum_init.N + (size_t) i]);
    for (int32_t i = 0; i < blind_rot.N; ++i) append_i32(out, blind_rot.polys[(size_t) i]);
    for (int32_t i = 0; i < blind_rot.N; ++i) append_i32(out, blind_rot.polys[(size_t) blind_rot.N + (size_t) i]);
    for (int32_t i = 0; i < pre_ks.n; ++i) append_i32(out, pre_ks.a[(size_t) i]);
    append_i32(out, pre_ks.b);
    return true;
}

static bool serialize_b1_vec(std::vector<uint8_t>& out, const ORHESignExtB1AccumulatorInitCheckpoint* ckpt) {
    append_envelope(out, SEM_KIND_B1);
    append_nested_bytes(out, &ckpt->pbs_input_ser);
    append_nested_bytes(out, &ckpt->accum_init_tlwe_ser);
    append_bytes(out, ckpt->ctx_root, 32);
    return true;
}

static bool serialize_b2_vec(std::vector<uint8_t>& out, const ORHESignExtB2BlindRotateCheckpoint* ckpt) {
    append_envelope(out, SEM_KIND_B2);
    append_nested_bytes(out, &ckpt->pbs_input_ser);
    append_nested_bytes(out, &ckpt->accum_init_tlwe_ser);
    append_nested_bytes(out, &ckpt->blind_rot_accum_tlwe_ser);
    append_bytes(out, ckpt->ctx_root, 32);
    return true;
}

static bool serialize_b3_vec(std::vector<uint8_t>& out, const ORHESignExtB3ExtractCheckpoint* ckpt) {
    append_envelope(out, SEM_KIND_B3);
    append_nested_bytes(out, &ckpt->blind_rot_accum_tlwe_ser);
    append_nested_bytes(out, &ckpt->pre_ks_lwe_ser);
    append_bytes(out, ckpt->ctx_root, 32);
    return true;
}

static bool serialize_b4_vec(std::vector<uint8_t>& out, const ORHESignExtB4InternalKsCheckpoint* ckpt) {
    append_envelope(out, SEM_KIND_B4);
    append_nested_bytes(out, &ckpt->pre_ks_lwe_ser);
    append_nested_bytes(out, &ckpt->c_sgn_ser);
    append_bytes(out, ckpt->pbs_ks_id, 32);
    append_bytes(out, ckpt->ctx_root, 32);
    return true;
}

static bool serialize_witness_vec(std::vector<uint8_t>& out, const ORHESignExtWitness* wit) {
    std::vector<uint8_t> b1;
    std::vector<uint8_t> b2;
    std::vector<uint8_t> b3;
    std::vector<uint8_t> b4;
    serialize_b1_vec(b1, &wit->b1);
    serialize_b2_vec(b2, &wit->b2);
    serialize_b3_vec(b3, &wit->b3);
    serialize_b4_vec(b4, &wit->b4);
    append_envelope(out, SEM_KIND_WIT);
    append_nested_bytes(out, &wit->pbs_input_ser);
    append_nested_bytes(out, &wit->pre_ks_lwe_ser);
    append_u64(out, (uint64_t) b1.size());
    append_bytes(out, b1.data(), b1.size());
    append_u64(out, (uint64_t) b2.size());
    append_bytes(out, b2.data(), b2.size());
    append_u64(out, (uint64_t) b3.size());
    append_bytes(out, b3.data(), b3.size());
    append_u64(out, (uint64_t) b4.size());
    append_bytes(out, b4.data(), b4.size());
    return true;
}

static void clear_b1_checkpoint(ORHESignExtB1AccumulatorInitCheckpoint* ckpt) {
    if (!ckpt) return;
    orhe_bytes_clear(&ckpt->pbs_input_ser);
    orhe_bytes_clear(&ckpt->accum_init_tlwe_ser);
    std::memset(ckpt->ctx_root, 0, sizeof(ckpt->ctx_root));
    ckpt->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

static void clear_b2_checkpoint(ORHESignExtB2BlindRotateCheckpoint* ckpt) {
    if (!ckpt) return;
    orhe_bytes_clear(&ckpt->pbs_input_ser);
    orhe_bytes_clear(&ckpt->accum_init_tlwe_ser);
    orhe_bytes_clear(&ckpt->blind_rot_accum_tlwe_ser);
    std::memset(ckpt->ctx_root, 0, sizeof(ckpt->ctx_root));
    ckpt->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

static void clear_b3_checkpoint(ORHESignExtB3ExtractCheckpoint* ckpt) {
    if (!ckpt) return;
    orhe_bytes_clear(&ckpt->blind_rot_accum_tlwe_ser);
    orhe_bytes_clear(&ckpt->pre_ks_lwe_ser);
    std::memset(ckpt->ctx_root, 0, sizeof(ckpt->ctx_root));
    ckpt->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

static bool deserialize_b1(const ORHEBytes* bytes, ORHESignExtB1AccumulatorInitCheckpoint* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->pbs_input_ser.ptr = NULL;
    out->pbs_input_ser.len = 0;
    out->accum_init_tlwe_ser.ptr = NULL;
    out->accum_init_tlwe_ser.len = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_B1)) return false;
    if (!cursor_read_nested_bytes(&cur, &out->pbs_input_ser) ||
        !cursor_read_nested_bytes(&cur, &out->accum_init_tlwe_ser) ||
        !cursor_read(&cur, out->ctx_root, 32) ||
        cur.off != cur.len) {
        clear_b1_checkpoint(out);
        return false;
    }
    return true;
}

static bool deserialize_b2(const ORHEBytes* bytes, ORHESignExtB2BlindRotateCheckpoint* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->pbs_input_ser.ptr = NULL;
    out->pbs_input_ser.len = 0;
    out->accum_init_tlwe_ser.ptr = NULL;
    out->accum_init_tlwe_ser.len = 0;
    out->blind_rot_accum_tlwe_ser.ptr = NULL;
    out->blind_rot_accum_tlwe_ser.len = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_B2)) return false;
    if (!cursor_read_nested_bytes(&cur, &out->pbs_input_ser) ||
        !cursor_read_nested_bytes(&cur, &out->accum_init_tlwe_ser) ||
        !cursor_read_nested_bytes(&cur, &out->blind_rot_accum_tlwe_ser) ||
        !cursor_read(&cur, out->ctx_root, 32) ||
        cur.off != cur.len) {
        clear_b2_checkpoint(out);
        return false;
    }
    return true;
}

static bool deserialize_b3(const ORHEBytes* bytes, ORHESignExtB3ExtractCheckpoint* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->blind_rot_accum_tlwe_ser.ptr = NULL;
    out->blind_rot_accum_tlwe_ser.len = 0;
    out->pre_ks_lwe_ser.ptr = NULL;
    out->pre_ks_lwe_ser.len = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_B3)) return false;
    if (!cursor_read_nested_bytes(&cur, &out->blind_rot_accum_tlwe_ser) ||
        !cursor_read_nested_bytes(&cur, &out->pre_ks_lwe_ser) ||
        !cursor_read(&cur, out->ctx_root, 32) ||
        cur.off != cur.len) {
        clear_b3_checkpoint(out);
        return false;
    }
    return true;
}

static bool deserialize_b4(const ORHEBytes* bytes, ORHESignExtB4InternalKsCheckpoint* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->pre_ks_lwe_ser.ptr = NULL;
    out->pre_ks_lwe_ser.len = 0;
    out->c_sgn_ser.ptr = NULL;
    out->c_sgn_ser.len = 0;
    if (!cursor_expect_envelope(&cur, SEM_KIND_B4)) return false;
    if (!cursor_read_nested_bytes(&cur, &out->pre_ks_lwe_ser) ||
        !cursor_read_nested_bytes(&cur, &out->c_sgn_ser) ||
        !cursor_read(&cur, out->pbs_ks_id, 32) ||
        !cursor_read(&cur, out->ctx_root, 32) ||
        cur.off != cur.len) {
        orhe_signext_b4_clear(out);
        return false;
    }
    return true;
}

static bool deserialize_witness(const ORHEBytes* bytes, ORHESignExtWitness* out) {
    BytesCursor cur = {bytes->ptr, bytes->len, 0};
    ORHEBytes b1_bytes;
    ORHEBytes b2_bytes;
    ORHEBytes b3_bytes;
    ORHEBytes b4_bytes;
    b1_bytes.ptr = NULL;
    b1_bytes.len = 0;
    b2_bytes.ptr = NULL;
    b2_bytes.len = 0;
    b3_bytes.ptr = NULL;
    b3_bytes.len = 0;
    b4_bytes.ptr = NULL;
    b4_bytes.len = 0;
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->pbs_input_ser.ptr = NULL;
    out->pbs_input_ser.len = 0;
    out->pre_ks_lwe_ser.ptr = NULL;
    out->pre_ks_lwe_ser.len = 0;
    std::memset(&out->b1, 0, sizeof(out->b1));
    std::memset(&out->b2, 0, sizeof(out->b2));
    std::memset(&out->b3, 0, sizeof(out->b3));
    std::memset(&out->b4, 0, sizeof(out->b4));
    if (!cursor_expect_envelope(&cur, SEM_KIND_WIT)) return false;
    if (!cursor_read_nested_bytes(&cur, &out->pbs_input_ser) ||
        !cursor_read_nested_bytes(&cur, &out->pre_ks_lwe_ser) ||
        !cursor_read_nested_bytes(&cur, &b1_bytes) ||
        !cursor_read_nested_bytes(&cur, &b2_bytes) ||
        !cursor_read_nested_bytes(&cur, &b3_bytes) ||
        !cursor_read_nested_bytes(&cur, &b4_bytes) ||
        cur.off != cur.len ||
        !deserialize_b1(&b1_bytes, &out->b1) ||
        !deserialize_b2(&b2_bytes, &out->b2) ||
        !deserialize_b3(&b3_bytes, &out->b3) ||
        !deserialize_b4(&b4_bytes, &out->b4)) {
        orhe_bytes_clear(&b1_bytes);
        orhe_bytes_clear(&b2_bytes);
        orhe_bytes_clear(&b3_bytes);
        orhe_bytes_clear(&b4_bytes);
        orhe_signext_witness_clear(out);
        return false;
    }
    orhe_bytes_clear(&b1_bytes);
    orhe_bytes_clear(&b2_bytes);
    orhe_bytes_clear(&b3_bytes);
    orhe_bytes_clear(&b4_bytes);
    return true;
}

static void hash_params_id(uint8_t out[32], const TFheGateBootstrappingParameterSet* params) {
    std::vector<uint8_t> bytes;
    append_i32(bytes, params->ks_t);
    append_i32(bytes, params->ks_basebit);
    append_i32(bytes, params->in_out_params->n);
    append_f64_bits(bytes, params->in_out_params->alpha_min);
    append_f64_bits(bytes, params->in_out_params->alpha_max);
    append_i32(bytes, params->tgsw_params->l);
    append_i32(bytes, params->tgsw_params->Bgbit);
    append_i32(bytes, params->tgsw_params->tlwe_params->N);
    append_i32(bytes, params->tgsw_params->tlwe_params->k);
    digest_bytes(out, 0x10u, bytes);
}

static void hash_lut_id(uint8_t out[32], const TFheGateBootstrappingParameterSet* params) {
    std::vector<uint8_t> bytes;
    static const Torus32 MU = modSwitchToTorus32(1, 8);
    append_bytes(bytes, "ORHE_SIGNEXT_LUT_V1", 19);
    append_i32(bytes, params->tgsw_params->tlwe_params->N);
    append_i32(bytes, MU);
    digest_bytes(out, 0x11u, bytes);
}

static void hash_bk_fft_id(uint8_t out[32], const TFheGateBootstrappingCloudKeySet* cloud) {
    digest_init(out, 0x12u);
    const TGswParams* bk_params = cloud->bk->bk_params;
    const int32_t n = cloud->bk->in_out_params->n;
    for (int32_t i = 0; i < n; ++i) {
        const TGswSample* sample = &cloud->bk->bk[i];
        for (int32_t row = 0; row < bk_params->kpl; ++row) {
            const TLweSample* tlwe = &sample->all_sample[row];
            for (int32_t poly = 0; poly <= tlwe->k; ++poly) {
                digest_mix(out, tlwe->a[poly].coefsT, sizeof(Torus32) * (size_t) bk_params->tlwe_params->N);
            }
            digest_mix(out, &tlwe->current_variance, sizeof(double));
        }
    }
}

static void hash_pbs_ks_id(uint8_t out[32], const LweKeySwitchKey* ks) {
    digest_init(out, 0x13u);
    digest_mix(out, &ks->n, sizeof(ks->n));
    digest_mix(out, &ks->t, sizeof(ks->t));
    digest_mix(out, &ks->basebit, sizeof(ks->basebit));
    digest_mix(out, &ks->out_params->n, sizeof(ks->out_params->n));
    for (int32_t i = 0; i < ks->n; ++i) {
        for (int32_t j = 0; j < ks->t; ++j) {
            for (int32_t p = 0; p < ks->base; ++p) {
                const LweSample* sample = &ks->ks[i][j][p];
                digest_mix(out, sample->a, sizeof(Torus32) * (size_t) ks->out_params->n);
                digest_mix(out, &sample->b, sizeof(sample->b));
                digest_mix(out, &sample->current_variance, sizeof(sample->current_variance));
            }
        }
    }
}

static void hash_ctx_root(uint8_t out[32], const ORHETFHEContextId* ctx) {
    digest_init(out, 0x14u);
    digest_mix(out, ctx->params_id, 32);
    digest_mix(out, ctx->lut_id, 32);
    digest_mix(out, ctx->bk_fft_id, 32);
    digest_mix(out, ctx->pbs_ks_id, 32);
}

static bool derive_signext_input_from_statement(
    const ORHESignExtPublicStatement* stmt,
    const ORHEKeySet* ks,
    ORHEBytes* out
) {
    ORHECiphertext* d = NULL;
    out->ptr = NULL;
    out->len = 0;
    if (!deserialize_ct_alloc(&stmt->d_ser, ks->tfhe_params, &d)) return false;
    bool ok = serialize_lwe_bytes(out, &d->bits[d->nbits - 1], ks->tfhe_params->in_out_params);
    orhe_delete_ciphertext(d);
    return ok;
}

static bool bytes_equal(const ORHEBytes* a, const ORHEBytes* b) {
    if (!a || !b || a->len != b->len) return false;
    if (a->len == 0) return true;
    return std::memcmp(a->ptr, b->ptr, (size_t) a->len) == 0;
}

static bool build_signext_accum_init(
    TLweSample* out,
    const LweSample* pbs_input,
    const ORHEKeySet* ks
) {
    static const Torus32 MU = modSwitchToTorus32(1, 8);
    const TLweParams* accum_params = ks->data_sk->cloud.bkFFT->accum_params;
    const int32_t N = accum_params->N;
    const int32_t two_n = 2 * N;
    const int32_t barb = modSwitchFromTorus32(pbs_input->b, two_n);

    TorusPolynomial* testvect = new_TorusPolynomial(N);
    TorusPolynomial* rotated = new_TorusPolynomial(N);
    for (int32_t i = 0; i < N; ++i) testvect->coefsT[i] = MU;
    if (barb != 0) torusPolynomialMulByXai(rotated, two_n - barb, testvect);
    else torusPolynomialCopy(rotated, testvect);
    tLweNoiselessTrivial(out, rotated, accum_params);
    delete_TorusPolynomial(rotated);
    delete_TorusPolynomial(testvect);
    return true;
}

static bool build_signext_bara(
    std::vector<int32_t>* out,
    const LweSample* pbs_input,
    const ORHEKeySet* ks
) {
    const LweParams* in_params = ks->data_sk->cloud.bkFFT->in_out_params;
    const int32_t n = in_params->n;
    const int32_t two_n = 2 * ks->data_sk->cloud.bkFFT->accum_params->N;
    out->assign((size_t) n, 0);
    for (int32_t i = 0; i < n; ++i) {
        (*out)[(size_t) i] = modSwitchFromTorus32(pbs_input->a[i], two_n);
    }
    return true;
}

static bool pack_semantic_proof_blob(
    ORHEBytes* out,
    const ORHEBytes* witness_bytes,
    const uint8_t* inner_ptr,
    uint64_t inner_len
) {
    std::vector<uint8_t> bytes;
    append_u32(bytes, ORHE_SIGNEXT_PROOF_MAGIC);
    append_u32(bytes, ORHE_SIGNEXT_SEMANTIC_VERSION);
    append_u64(bytes, witness_bytes->len);
    append_u64(bytes, inner_len);
    if (witness_bytes->len > 0) append_bytes(bytes, witness_bytes->ptr, (size_t) witness_bytes->len);
    if (inner_len > 0) append_bytes(bytes, inner_ptr, (size_t) inner_len);
    return orhe_bytes_assign(out, bytes);
}

static bool unpack_semantic_proof_blob(
    const ORHEProof* proof,
    ORHEBytes* witness_bytes,
    ORHEBytes* inner_proof_bytes
) {
    BytesCursor cur = {proof->blob, proof->blob_len, 0};
    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t wit_len = 0;
    uint64_t inner_len = 0;
    witness_bytes->ptr = NULL;
    witness_bytes->len = 0;
    inner_proof_bytes->ptr = NULL;
    inner_proof_bytes->len = 0;
    if (!cursor_read_u32(&cur, &magic) ||
        !cursor_read_u32(&cur, &version) ||
        !cursor_read_u64(&cur, &wit_len) ||
        !cursor_read_u64(&cur, &inner_len) ||
        magic != ORHE_SIGNEXT_PROOF_MAGIC ||
        version != ORHE_SIGNEXT_SEMANTIC_VERSION) {
        return false;
    }
    witness_bytes->len = wit_len;
    if (wit_len > 0) {
        witness_bytes->ptr = (uint8_t*) std::malloc((size_t) wit_len);
        if (!witness_bytes->ptr || !cursor_read(&cur, witness_bytes->ptr, wit_len)) {
            orhe_bytes_clear(witness_bytes);
            return false;
        }
    }
    inner_proof_bytes->ptr = NULL;
    inner_proof_bytes->len = inner_len;
    if (inner_len > 0) {
        inner_proof_bytes->ptr = (uint8_t*) std::malloc((size_t) inner_len);
        if (!inner_proof_bytes->ptr || !cursor_read(&cur, inner_proof_bytes->ptr, inner_len)) {
            orhe_bytes_clear(witness_bytes);
            orhe_bytes_clear(inner_proof_bytes);
            return false;
        }
    }
    if (cur.off != cur.len) {
        orhe_bytes_clear(witness_bytes);
        orhe_bytes_clear(inner_proof_bytes);
        return false;
    }
    return true;
}

static bool validate_b1_checkpoint(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    ParsedTlweBytes accum_init;
    if (!ks) return false;
    if (!bytes_equal(&stmt->pbs_input_ser, &wit->pbs_input_ser)) return false;
    if (!bytes_equal(&wit->pbs_input_ser, &wit->b1.pbs_input_ser)) return false;
    if (std::memcmp(wit->b1.ctx_root, stmt->tfhe_ctx_id.ctx_root, 32) != 0) return false;
    if (!parse_tlwe_bytes_generic(&wit->b1.accum_init_tlwe_ser, &accum_init)) return false;
    if (accum_init.k != ks->data_sk->cloud.bkFFT->accum_params->k ||
        accum_init.N != ks->data_sk->cloud.bkFFT->accum_params->N) {
        return false;
    }
    return accum_init.current_variance == 0.;
}

static bool validate_b2_checkpoint(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    TLweSample* init_accum = NULL;
    TLweSample* claimed = NULL;
    TLweSample* expected = NULL;
    LweSample* pbs_input = NULL;
    std::vector<int32_t> bara;

    if (!bytes_equal(&wit->pbs_input_ser, &wit->b2.pbs_input_ser)) return false;
    if (!bytes_equal(&wit->b1.accum_init_tlwe_ser, &wit->b2.accum_init_tlwe_ser)) return false;
    if (std::memcmp(wit->b2.ctx_root, stmt->tfhe_ctx_id.ctx_root, 32) != 0) return false;
    if (!deserialize_lwe_alloc(&wit->pbs_input_ser, ks->tfhe_params->in_out_params, &pbs_input)) return false;
    if (!deserialize_tlwe_alloc(&wit->b2.accum_init_tlwe_ser, ks->data_sk->cloud.bkFFT->accum_params, &init_accum) ||
        !deserialize_tlwe_alloc(&wit->b2.blind_rot_accum_tlwe_ser, ks->data_sk->cloud.bkFFT->accum_params, &claimed)) {
        delete_LweSample(pbs_input);
        if (init_accum) delete_TLweSample(init_accum);
        return false;
    }
    expected = new_TLweSample(ks->data_sk->cloud.bkFFT->accum_params);
    tLweCopy(expected, init_accum, ks->data_sk->cloud.bkFFT->accum_params);
    build_signext_bara(&bara, pbs_input, ks);
    tfhe_blindRotate_FFT(
        expected,
        ks->data_sk->cloud.bkFFT->bkFFT,
        bara.data(),
        ks->data_sk->cloud.bkFFT->in_out_params->n,
        ks->data_sk->cloud.bkFFT->bk_params
    );
    bool ok = tlwe_equal(expected, claimed, ks->data_sk->cloud.bkFFT->accum_params);
    delete_TLweSample(expected);
    delete_TLweSample(claimed);
    delete_TLweSample(init_accum);
    delete_LweSample(pbs_input);
    return ok;
}

static bool validate_b3_checkpoint(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    ParsedTlweBytes blind_rot;
    ParsedLweBytes pre_ks;
    if (!ks) return false;
    if (!bytes_equal(&wit->b2.blind_rot_accum_tlwe_ser, &wit->b3.blind_rot_accum_tlwe_ser)) return false;
    if (!bytes_equal(&wit->pre_ks_lwe_ser, &wit->b3.pre_ks_lwe_ser)) return false;
    if (std::memcmp(wit->b3.ctx_root, stmt->tfhe_ctx_id.ctx_root, 32) != 0) return false;
    if (!parse_tlwe_bytes_generic(&wit->b3.blind_rot_accum_tlwe_ser, &blind_rot) ||
        !parse_lwe_bytes_generic(&wit->b3.pre_ks_lwe_ser, &pre_ks)) {
        return false;
    }
    if (blind_rot.k != ks->data_sk->cloud.bkFFT->accum_params->k ||
        blind_rot.N != ks->data_sk->cloud.bkFFT->accum_params->N ||
        pre_ks.n != ks->data_sk->cloud.bkFFT->extract_params->n) {
        return false;
    }
    if (pre_ks.current_variance != 0.) return false;
    return !has_int32_min_negation_hazard(&blind_rot);
}

static bool validate_partial_signext_statement(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    ORHEBytes expected_input;
    expected_input.ptr = NULL;
    expected_input.len = 0;
    if (!stmt || !wit || !ks) return false;
    if (stmt->relation_id != ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3) return false;
    if (!orhe_signext_validate_tfhe_ctx_id(&stmt->tfhe_ctx_id, ks)) return false;
    if (!derive_signext_input_from_statement(stmt, ks, &expected_input)) return false;
    const bool ok = bytes_equal(&expected_input, &stmt->pbs_input_ser) &&
                    bytes_equal(&stmt->pbs_input_ser, &wit->pbs_input_ser);
    orhe_bytes_clear(&expected_input);
    return ok;
}

static bool validate_b4_checkpoint(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    ORHEBytes expected_input;
    expected_input.ptr = NULL;
    expected_input.len = 0;
    LweSample* pre_ks = NULL;
    LweSample* claimed = NULL;
    LweSample* expected = NULL;

    if (std::memcmp(wit->b4.pbs_ks_id, stmt->tfhe_ctx_id.pbs_ks_id, 32) != 0) return false;
    if (std::memcmp(wit->b4.ctx_root, stmt->tfhe_ctx_id.ctx_root, 32) != 0) return false;
    if (!bytes_equal(&wit->pre_ks_lwe_ser, &wit->b4.pre_ks_lwe_ser)) return false;
    if (!bytes_equal(&stmt->c_sgn_ser, &wit->b4.c_sgn_ser)) return false;
    if (!derive_signext_input_from_statement(stmt, ks, &expected_input)) return false;
    if (!bytes_equal(&expected_input, &wit->pbs_input_ser)) {
        orhe_bytes_clear(&expected_input);
        return false;
    }
    orhe_bytes_clear(&expected_input);

    if (!deserialize_lwe_alloc(&wit->pre_ks_lwe_ser, ks->data_sk->cloud.bkFFT->extract_params, &pre_ks)) return false;
    if (!deserialize_lwe_alloc(&stmt->c_sgn_ser, ks->tfhe_params->in_out_params, &claimed)) {
        delete_LweSample(pre_ks);
        return false;
    }
    expected = new_LweSample(ks->tfhe_params->in_out_params);
    lweKeySwitch(expected, ks->data_sk->cloud.bkFFT->ks, pre_ks);

    bool ok = lwe_equal(expected, claimed, ks->tfhe_params->in_out_params);
    delete_LweSample(expected);
    delete_LweSample(claimed);
    delete_LweSample(pre_ks);
    return ok;
}

static bool validate_signext_semantic_witness(
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    return validate_partial_signext_statement(stmt, wit, ks) &&
           validate_b1_checkpoint(stmt, wit, ks) &&
           validate_b2_checkpoint(stmt, wit, ks) &&
           validate_b3_checkpoint(stmt, wit, ks) &&
           validate_b4_checkpoint(stmt, wit, ks);
}

}  // namespace

void orhe_bytes_clear(ORHEBytes* bytes) {
    if (!bytes) return;
    if (bytes->ptr) std::free(bytes->ptr);
    bytes->ptr = NULL;
    bytes->len = 0;
}

void orhe_signext_b4_clear(ORHESignExtB4InternalKsCheckpoint* ckpt) {
    if (!ckpt) return;
    orhe_bytes_clear(&ckpt->pre_ks_lwe_ser);
    orhe_bytes_clear(&ckpt->c_sgn_ser);
    std::memset(ckpt->pbs_ks_id, 0, sizeof(ckpt->pbs_ks_id));
    std::memset(ckpt->ctx_root, 0, sizeof(ckpt->ctx_root));
    ckpt->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

void orhe_signext_public_statement_clear(ORHESignExtPublicStatement* stmt) {
    if (!stmt) return;
    orhe_bytes_clear(&stmt->d_ser);
    orhe_bytes_clear(&stmt->pbs_input_ser);
    orhe_bytes_clear(&stmt->c_sgn_ser);
    stmt->relation_id = ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3;
    std::memset(&stmt->tfhe_ctx_id, 0, sizeof(stmt->tfhe_ctx_id));
    stmt->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

void orhe_signext_witness_clear(ORHESignExtWitness* wit) {
    if (!wit) return;
    orhe_bytes_clear(&wit->pbs_input_ser);
    orhe_bytes_clear(&wit->pre_ks_lwe_ser);
    clear_b1_checkpoint(&wit->b1);
    clear_b2_checkpoint(&wit->b2);
    clear_b3_checkpoint(&wit->b3);
    orhe_signext_b4_clear(&wit->b4);
    wit->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
}

int32_t orhe_signext_build_tfhe_ctx_id(
    ORHETFHEContextId* out,
    const ORHEKeySet* ks
) {
    if (!out || !ks || !ks->tfhe_params || !ks->data_sk) return 0;
    hash_params_id(out->params_id, ks->tfhe_params);
    hash_lut_id(out->lut_id, ks->tfhe_params);
    hash_bk_fft_id(out->bk_fft_id, &ks->data_sk->cloud);
    hash_pbs_ks_id(out->pbs_ks_id, ks->data_sk->cloud.bkFFT->ks);
    hash_ctx_root(out->ctx_root, out);
    return 1;
}

int32_t orhe_signext_validate_tfhe_ctx_id(
    const ORHETFHEContextId* expected,
    const ORHEKeySet* ks
) {
    ORHETFHEContextId actual;
    if (!expected || !orhe_signext_build_tfhe_ctx_id(&actual, ks)) return 0;
    return std::memcmp(&actual, expected, sizeof(actual)) == 0 ? 1 : 0;
}

int32_t orhe_signext_build_public_statement(
    ORHESignExtPublicStatement* out,
    const ORHECiphertext* d,
    const LweSample* c_sgn,
    const ORHEKeySet* ks
) {
    if (!out || !d || !c_sgn || !ks) return 0;
    orhe_signext_public_statement_clear(out);
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->relation_id = ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3;
    if (!serialize_ct_bytes(&out->d_ser, d) ||
        !serialize_lwe_bytes(&out->pbs_input_ser, &d->bits[d->nbits - 1], ks->tfhe_params->in_out_params) ||
        !serialize_lwe_bytes(&out->c_sgn_ser, c_sgn, ks->tfhe_params->in_out_params) ||
        !orhe_signext_build_tfhe_ctx_id(&out->tfhe_ctx_id, ks)) {
        orhe_signext_public_statement_clear(out);
        return 0;
    }
    return 1;
}

int32_t orhe_signext_build_witness(
    ORHESignExtWitness* out,
    const ORHECiphertext* d,
    const LweSample* c_sgn,
    const ORHEKeySet* ks
) {
    ORHETFHEContextId ctx_id;
    TLweSample* accum_init = NULL;
    TLweSample* blind_rot_accum = NULL;
    LweSample* pre_ks = NULL;
    LweSample* expected = NULL;
    std::vector<int32_t> bara;

    if (!out || !d || !c_sgn || !ks) return 0;
    orhe_signext_witness_clear(out);
    out->version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->b1.version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->b2.version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->b3.version = ORHE_SIGNEXT_SEMANTIC_VERSION;
    out->b4.version = ORHE_SIGNEXT_SEMANTIC_VERSION;

    if (!serialize_lwe_bytes(&out->pbs_input_ser, &d->bits[d->nbits - 1], ks->tfhe_params->in_out_params)) {
        orhe_signext_witness_clear(out);
        return 0;
    }

    accum_init = new_TLweSample(ks->data_sk->cloud.bkFFT->accum_params);
    blind_rot_accum = new_TLweSample(ks->data_sk->cloud.bkFFT->accum_params);
    pre_ks = new_LweSample(ks->data_sk->cloud.bkFFT->extract_params);
    build_signext_accum_init(accum_init, &d->bits[d->nbits - 1], ks);
    tLweCopy(blind_rot_accum, accum_init, ks->data_sk->cloud.bkFFT->accum_params);
    build_signext_bara(&bara, &d->bits[d->nbits - 1], ks);
    tfhe_blindRotate_FFT(
        blind_rot_accum,
        ks->data_sk->cloud.bkFFT->bkFFT,
        bara.data(),
        ks->data_sk->cloud.bkFFT->in_out_params->n,
        ks->data_sk->cloud.bkFFT->bk_params
    );
    tLweExtractLweSample(
        pre_ks,
        blind_rot_accum,
        ks->data_sk->cloud.bkFFT->extract_params,
        ks->data_sk->cloud.bkFFT->accum_params
    );
    expected = new_LweSample(ks->tfhe_params->in_out_params);
    lweKeySwitch(expected, ks->data_sk->cloud.bkFFT->ks, pre_ks);
    if (!orhe_signext_build_tfhe_ctx_id(&ctx_id, ks) ||
        !serialize_lwe_bytes(&out->pre_ks_lwe_ser, pre_ks, ks->data_sk->cloud.bkFFT->extract_params) ||
        !serialize_lwe_bytes(&out->b1.pbs_input_ser, &d->bits[d->nbits - 1], ks->tfhe_params->in_out_params) ||
        !serialize_tlwe_bytes(&out->b1.accum_init_tlwe_ser, accum_init, ks->data_sk->cloud.bkFFT->accum_params) ||
        !serialize_lwe_bytes(&out->b2.pbs_input_ser, &d->bits[d->nbits - 1], ks->tfhe_params->in_out_params) ||
        !serialize_tlwe_bytes(&out->b2.accum_init_tlwe_ser, accum_init, ks->data_sk->cloud.bkFFT->accum_params) ||
        !serialize_tlwe_bytes(&out->b2.blind_rot_accum_tlwe_ser, blind_rot_accum, ks->data_sk->cloud.bkFFT->accum_params) ||
        !serialize_tlwe_bytes(&out->b3.blind_rot_accum_tlwe_ser, blind_rot_accum, ks->data_sk->cloud.bkFFT->accum_params) ||
        !serialize_lwe_bytes(&out->b3.pre_ks_lwe_ser, pre_ks, ks->data_sk->cloud.bkFFT->extract_params) ||
        !serialize_lwe_bytes(&out->b4.pre_ks_lwe_ser, pre_ks, ks->data_sk->cloud.bkFFT->extract_params) ||
        !serialize_lwe_bytes(&out->b4.c_sgn_ser, c_sgn, ks->tfhe_params->in_out_params) ||
        !lwe_equal(expected, c_sgn, ks->tfhe_params->in_out_params)) {
        delete_LweSample(expected);
        delete_LweSample(pre_ks);
        delete_TLweSample(blind_rot_accum);
        delete_TLweSample(accum_init);
        orhe_signext_witness_clear(out);
        return 0;
    }
    std::memcpy(out->b1.ctx_root, ctx_id.ctx_root, sizeof(ctx_id.ctx_root));
    std::memcpy(out->b2.ctx_root, ctx_id.ctx_root, sizeof(ctx_id.ctx_root));
    std::memcpy(out->b3.ctx_root, ctx_id.ctx_root, sizeof(ctx_id.ctx_root));
    std::memcpy(out->b4.pbs_ks_id, ctx_id.pbs_ks_id, sizeof(ctx_id.pbs_ks_id));
    std::memcpy(out->b4.ctx_root, ctx_id.ctx_root, sizeof(ctx_id.ctx_root));
    delete_LweSample(expected);
    delete_LweSample(pre_ks);
    delete_TLweSample(blind_rot_accum);
    delete_TLweSample(accum_init);
    return 1;
}

void orhe_proof_prove_signext_semantic(
    ORHEProof* out,
    const ORHEProofPP* pp,
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit
) {
    ORHEBytes backend_stmt_bytes;
    ORHEBytes backend_wit_bytes;
    ORHEBytes outer_wit_bytes;
    ORHEBytes proof_blob;
    uint8_t* inner_ptr = NULL;
    uint64_t inner_len = 0;

    backend_stmt_bytes.ptr = NULL;
    backend_stmt_bytes.len = 0;
    backend_wit_bytes.ptr = NULL;
    backend_wit_bytes.len = 0;
    outer_wit_bytes.ptr = NULL;
    outer_wit_bytes.len = 0;
    proof_blob.ptr = NULL;
    proof_blob.len = 0;

    out->family = ORHE_PROOF_FAMILY_NONE;
    out->blob = NULL;
    out->blob_len = 0;
    out->owns_backend_buffer = 0;

    if (!pp || pp->backend_mode != ORHE_BACKEND_MODE_SIGNEXT_PARTIAL_SEMANTIC_B1_B3 || !stmt || !wit) return;

    {
        std::vector<uint8_t> stmt_vec;
        std::vector<uint8_t> wit_vec;
        if (!build_partial_backend_statement_vec(stmt_vec, stmt) ||
            !build_partial_backend_witness_vec(wit_vec, wit) ||
            !orhe_bytes_assign(&backend_stmt_bytes, stmt_vec) ||
            !orhe_bytes_assign(&backend_wit_bytes, wit_vec)) {
            goto cleanup;
        }
    }

    {
        std::vector<uint8_t> outer_wit_vec;
        serialize_witness_vec(outer_wit_vec, wit);
        if (!orhe_bytes_assign(&outer_wit_bytes, outer_wit_vec)) goto cleanup;
    }

    if (!orhe_backend_prove_signext_semantic_bridge(
            (void*) pp->backend,
            backend_stmt_bytes.ptr,
            backend_stmt_bytes.len,
            backend_wit_bytes.ptr,
            backend_wit_bytes.len,
            &inner_ptr,
            &inner_len)) {
        goto cleanup;
    }

    if (!pack_semantic_proof_blob(&proof_blob, &outer_wit_bytes, inner_ptr, inner_len)) goto cleanup;

    out->family = ORHE_PROOF_FAMILY_SIGNEXT;
    out->blob = proof_blob.ptr;
    out->blob_len = proof_blob.len;
    out->owns_backend_buffer = 0;
    proof_blob.ptr = NULL;
    proof_blob.len = 0;

cleanup:
    if (inner_ptr) orhe_backend_free_buffer_bridge(inner_ptr, inner_len);
    orhe_bytes_clear(&backend_stmt_bytes);
    orhe_bytes_clear(&backend_wit_bytes);
    orhe_bytes_clear(&outer_wit_bytes);
    orhe_bytes_clear(&proof_blob);
}

int32_t orhe_proof_verify_signext_semantic(
    const ORHEProofPP* pp,
    const ORHESignExtPublicStatement* stmt,
    const ORHEProof* proof,
    const ORHEKeySet* ks
) {
    ORHEBytes backend_stmt_bytes;
    ORHEBytes backend_wit_bytes;
    ORHEBytes outer_wit_bytes;
    ORHEBytes inner_bytes;
    ORHESignExtWitness wit;
    int32_t ok = 0;

    backend_stmt_bytes.ptr = NULL;
    backend_stmt_bytes.len = 0;
    backend_wit_bytes.ptr = NULL;
    backend_wit_bytes.len = 0;
    outer_wit_bytes.ptr = NULL;
    outer_wit_bytes.len = 0;
    inner_bytes.ptr = NULL;
    inner_bytes.len = 0;
    std::memset(&wit, 0, sizeof(wit));

    if (!pp || !stmt || !proof || !ks) return 0;
    if (pp->backend_mode != ORHE_BACKEND_MODE_SIGNEXT_PARTIAL_SEMANTIC_B1_B3) return 0;
    if (proof->family != ORHE_PROOF_FAMILY_SIGNEXT) return 0;

    if (!unpack_semantic_proof_blob(proof, &outer_wit_bytes, &inner_bytes) ||
        !deserialize_witness(&outer_wit_bytes, &wit) ||
        !validate_signext_semantic_witness(stmt, &wit, ks)) {
        goto cleanup;
    }

    {
        std::vector<uint8_t> stmt_vec;
        std::vector<uint8_t> wit_vec;
        if (!build_partial_backend_statement_vec(stmt_vec, stmt) ||
            !build_partial_backend_witness_vec(wit_vec, &wit) ||
            !orhe_bytes_assign(&backend_stmt_bytes, stmt_vec) ||
            !orhe_bytes_assign(&backend_wit_bytes, wit_vec)) {
            goto cleanup;
        }
    }

    ok = orhe_backend_verify_signext_semantic_bridge(
        (void*) pp->backend,
        backend_stmt_bytes.ptr,
        backend_stmt_bytes.len,
        backend_wit_bytes.ptr,
        backend_wit_bytes.len,
        inner_bytes.ptr,
        inner_bytes.len
    );

cleanup:
    orhe_signext_witness_clear(&wit);
    orhe_bytes_clear(&backend_stmt_bytes);
    orhe_bytes_clear(&backend_wit_bytes);
    orhe_bytes_clear(&outer_wit_bytes);
    orhe_bytes_clear(&inner_bytes);
    return ok;
}
