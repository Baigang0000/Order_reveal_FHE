#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

static const uint32_t ORHE_MOCK_PROOF_MAGIC = 0x4f484d50u;  // "OHMP"
static const uint64_t ORHE_MOCK_PROOF_LEN = 60;

struct MockBackendPP {
    int32_t family;
    int32_t bit_width;
};

static void store_u32_le(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t) (value & 0xffu);
    out[1] = (uint8_t) ((value >> 8) & 0xffu);
    out[2] = (uint8_t) ((value >> 16) & 0xffu);
    out[3] = (uint8_t) ((value >> 24) & 0xffu);
}

static void store_u64_le(uint8_t* out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out[i] = (uint8_t) ((value >> (8 * i)) & 0xffu);
    }
}

static uint32_t load_u32_le(const uint8_t* in) {
    return
        ((uint32_t) in[0]) |
        ((uint32_t) in[1] << 8) |
        ((uint32_t) in[2] << 16) |
        ((uint32_t) in[3] << 24);
}

static uint64_t load_u64_le(const uint8_t* in) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= ((uint64_t) in[i]) << (8 * i);
    }
    return value;
}

static void digest_init(uint8_t out[32], int32_t family, int32_t bit_width) {
    for (int i = 0; i < 32; ++i) {
        out[i] = (uint8_t) (0x5a + (3 * i) + (family * 11) + bit_width);
    }
}

static void digest_mix_bytes(uint8_t digest[32], const uint8_t* bytes, uint64_t len) {
    if (!bytes && len != 0) return;

    for (uint64_t i = 0; i < len; ++i) {
        uint8_t v = bytes[i];
        digest[i % 32] ^= (uint8_t) (v + (uint8_t) i + 17u);
        digest[(i * 7u) % 32] =
            (uint8_t) (digest[(i * 7u) % 32] + v + (uint8_t) ((i * 13u) & 0xffu));
        digest[(i * 13u) % 32] ^=
            (uint8_t) ((v << (i & 3u)) | (v >> (8u - (i & 3u))));
    }
}

static void digest_mix_u64(uint8_t digest[32], uint64_t value) {
    uint8_t bytes[8];
    store_u64_le(bytes, value);
    digest_mix_bytes(digest, bytes, sizeof(bytes));
}

static void compute_digest(
    uint8_t out[32],
    const MockBackendPP* pp,
    const uint8_t* left_ptr,
    uint64_t left_len,
    const uint8_t* right_ptr,
    uint64_t right_len
) {
    digest_init(out, pp->family, pp->bit_width);
    digest_mix_u64(out, (uint64_t) (uint32_t) pp->family);
    digest_mix_u64(out, (uint64_t) (uint32_t) pp->bit_width);
    digest_mix_u64(out, left_len);
    digest_mix_bytes(out, left_ptr, left_len);
    digest_mix_u64(out, right_len);
    digest_mix_bytes(out, right_ptr, right_len);
}

static int32_t prove_pair(
    MockBackendPP* pp,
    const uint8_t* left_ptr,
    uint64_t left_len,
    const uint8_t* right_ptr,
    uint64_t right_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    if (!pp || !out_ptr || !out_len) return 0;
    if ((!left_ptr && left_len != 0) || (!right_ptr && right_len != 0)) return 0;

    uint8_t digest[32];
    compute_digest(digest, pp, left_ptr, left_len, right_ptr, right_len);

    uint8_t* blob = (uint8_t*) std::malloc((size_t) ORHE_MOCK_PROOF_LEN);
    if (!blob) return 0;

    store_u32_le(blob + 0, ORHE_MOCK_PROOF_MAGIC);
    store_u32_le(blob + 4, (uint32_t) pp->family);
    store_u32_le(blob + 8, (uint32_t) pp->bit_width);
    store_u64_le(blob + 12, left_len);
    store_u64_le(blob + 20, right_len);
    std::memcpy(blob + 28, digest, sizeof(digest));

    *out_ptr = blob;
    *out_len = ORHE_MOCK_PROOF_LEN;
    return 1;
}

static int32_t verify_pair(
    MockBackendPP* pp,
    const uint8_t* left_ptr,
    uint64_t left_len,
    const uint8_t* right_ptr,
    uint64_t right_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    if (!pp || !proof_ptr) return 0;
    if ((!left_ptr && left_len != 0) || (!right_ptr && right_len != 0)) return 0;
    if (proof_len != ORHE_MOCK_PROOF_LEN) return 0;

    if (load_u32_le(proof_ptr + 0) != ORHE_MOCK_PROOF_MAGIC) return 0;
    if ((int32_t) load_u32_le(proof_ptr + 4) != pp->family) return 0;
    if ((int32_t) load_u32_le(proof_ptr + 8) != pp->bit_width) return 0;
    if (load_u64_le(proof_ptr + 12) != left_len) return 0;
    if (load_u64_le(proof_ptr + 20) != right_len) return 0;

    uint8_t digest[32];
    compute_digest(digest, pp, left_ptr, left_len, right_ptr, right_len);
    return std::memcmp(proof_ptr + 28, digest, sizeof(digest)) == 0 ? 1 : 0;
}

}  // namespace

extern "C" {

void* orhe_rust_setup_pp(int32_t family, int32_t bit_width) {
    MockBackendPP* pp = (MockBackendPP*) std::malloc(sizeof(MockBackendPP));
    if (!pp) return NULL;
    pp->family = family;
    pp->bit_width = bit_width;
    return pp;
}

void* orhe_rust_setup_signext_semantic_pp(int32_t bit_width) {
    return orhe_rust_setup_pp(2, bit_width);
}

void orhe_rust_free_pp(void* handle) {
    std::free(handle);
}

int32_t orhe_rust_prove_pbs(
    void* handle,
    const uint8_t* x_ptr,
    uint64_t x_len,
    const uint8_t* y_ptr,
    uint64_t y_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return prove_pair(
        (MockBackendPP*) handle,
        x_ptr,
        x_len,
        y_ptr,
        y_len,
        out_ptr,
        out_len
    );
}

int32_t orhe_rust_verify_pbs(
    void* handle,
    const uint8_t* x_ptr,
    uint64_t x_len,
    const uint8_t* y_ptr,
    uint64_t y_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return verify_pair(
        (MockBackendPP*) handle,
        x_ptr,
        x_len,
        y_ptr,
        y_len,
        proof_ptr,
        proof_len
    );
}

int32_t orhe_rust_prove_signext(
    void* handle,
    const uint8_t* d_ptr,
    uint64_t d_len,
    const uint8_t* s_ptr,
    uint64_t s_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return prove_pair(
        (MockBackendPP*) handle,
        d_ptr,
        d_len,
        s_ptr,
        s_len,
        out_ptr,
        out_len
    );
}

int32_t orhe_rust_verify_signext(
    void* handle,
    const uint8_t* d_ptr,
    uint64_t d_len,
    const uint8_t* s_ptr,
    uint64_t s_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return verify_pair(
        (MockBackendPP*) handle,
        d_ptr,
        d_len,
        s_ptr,
        s_len,
        proof_ptr,
        proof_len
    );
}

int32_t orhe_rust_prove_signext_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return prove_pair(
        (MockBackendPP*) handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        out_ptr,
        out_len
    );
}

int32_t orhe_rust_verify_signext_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return verify_pair(
        (MockBackendPP*) handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        proof_ptr,
        proof_len
    );
}

int32_t orhe_rust_prove_ks(
    void* handle,
    const uint8_t* s_ptr,
    uint64_t s_len,
    const uint8_t* u_ptr,
    uint64_t u_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return prove_pair(
        (MockBackendPP*) handle,
        s_ptr,
        s_len,
        u_ptr,
        u_len,
        out_ptr,
        out_len
    );
}

int32_t orhe_rust_verify_ks(
    void* handle,
    const uint8_t* s_ptr,
    uint64_t s_len,
    const uint8_t* u_ptr,
    uint64_t u_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return verify_pair(
        (MockBackendPP*) handle,
        s_ptr,
        s_len,
        u_ptr,
        u_len,
        proof_ptr,
        proof_len
    );
}

void orhe_rust_free_buffer(uint8_t* ptr, uint64_t len) {
    (void) len;
    std::free(ptr);
}

}  // extern "C"
