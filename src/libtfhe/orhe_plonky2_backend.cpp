#include "orhe_plonky2_backend.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" {

// Rust FFI exports
void* orhe_rust_setup_pp(int32_t family, int32_t bit_width);
void* orhe_rust_setup_pbs_semantic_pp(int32_t bit_width, int32_t lwe_n);
void* orhe_rust_setup_signext_semantic_pp(int32_t bit_width);
void orhe_rust_free_pp(void* handle);

int32_t orhe_rust_prove_pbs(
    void* handle,
    const uint8_t* x_ptr, uint64_t x_len,
    const uint8_t* y_ptr, uint64_t y_len,
    uint8_t** out_ptr, uint64_t* out_len
);

int32_t orhe_rust_verify_pbs(
    void* handle,
    const uint8_t* x_ptr, uint64_t x_len,
    const uint8_t* y_ptr, uint64_t y_len,
    const uint8_t* proof_ptr, uint64_t proof_len
);
int32_t orhe_rust_prove_pbs_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
);
int32_t orhe_rust_verify_pbs_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

int32_t orhe_rust_prove_signext(
    void* handle,
    const uint8_t* d_ptr, uint64_t d_len,
    const uint8_t* s_ptr, uint64_t s_len,
    const uint8_t* t_ptr, uint64_t t_len,
    const uint8_t* w_ptr, uint64_t w_len,
    uint8_t** out_ptr, uint64_t* out_len
);

int32_t orhe_rust_verify_signext(
    void* handle,
    const uint8_t* d_ptr, uint64_t d_len,
    const uint8_t* s_ptr, uint64_t s_len,
    const uint8_t* t_ptr, uint64_t t_len,
    const uint8_t* proof_ptr, uint64_t proof_len
);

int32_t orhe_rust_prove_signext_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
);

int32_t orhe_rust_verify_signext_semantic(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
);

int32_t orhe_rust_prove_ks(
    void* handle,
    const uint8_t* s_ptr, uint64_t s_len,
    const uint8_t* u_ptr, uint64_t u_len,
    uint8_t** out_ptr, uint64_t* out_len
);

int32_t orhe_rust_verify_ks(
    void* handle,
    const uint8_t* s_ptr, uint64_t s_len,
    const uint8_t* u_ptr, uint64_t u_len,
    const uint8_t* proof_ptr, uint64_t proof_len
);

void orhe_rust_free_buffer(uint8_t* ptr, uint64_t len);
}

static void append_bytes(std::vector<uint8_t>& out, const void* ptr, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(ptr);
    out.insert(out.end(), p, p + len);
}

static bool debug_compare_enabled() {
    const char* v = std::getenv("ORHE_DEBUG_COMPARE");
    return v && std::strcmp(v, "1") == 0;
}

static bool debug_compare_full_enabled() {
    const char* v = std::getenv("ORHE_DEBUG_COMPARE_FULL");
    return v && std::strcmp(v, "1") == 0;
}

static uint64_t fnv1a64(const uint8_t* data, size_t len) {
    uint64_t acc = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        acc ^= (uint64_t) data[i];
        acc *= 0x100000001b3ULL;
    }
    return acc;
}

static std::string hex_preview(const std::vector<uint8_t>& bytes) {
    static const char* kHex = "0123456789abcdef";
    auto append_hex = [&](std::string& out, const uint8_t* data, size_t len) {
        out.reserve(out.size() + 2 * len);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(kHex[data[i] >> 4]);
            out.push_back(kHex[data[i] & 0x0f]);
        }
    };

    std::string out;
    if (debug_compare_full_enabled() || bytes.size() <= 64) {
        append_hex(out, bytes.data(), bytes.size());
        return out;
    }

    append_hex(out, bytes.data(), 64);
    out += "...";
    append_hex(out, bytes.data() + bytes.size() - 16, 16);
    return out;
}

static void debug_dump_bytes(const char* label, const std::vector<uint8_t>& bytes) {
    std::fprintf(
        stderr,
        "[c++][compare-debug] %s: len=%zu fnv64=%016llx hex=%s\n",
        label,
        bytes.size(),
        (unsigned long long) fnv1a64(bytes.data(), bytes.size()),
        hex_preview(bytes).c_str()
    );
}

static void debug_dump_proof(const char* label, const uint8_t* ptr, uint64_t len) {
    std::vector<uint8_t> bytes;
    bytes.resize((size_t) len);
    if (ptr && len > 0) {
        std::memcpy(bytes.data(), ptr, (size_t) len);
    }
    debug_dump_bytes(label, bytes);
}

static std::vector<uint8_t> serialize_ct(const ORHECiphertext* ct) {
    std::vector<uint8_t> out;
    append_bytes(out, &ct->nbits, sizeof(ct->nbits));

    int32_t n = ct->lwe_params->n;
    append_bytes(out, &n, sizeof(n));

    for (int32_t i = 0; i < ct->nbits; ++i) {
        const LweSample* s = &ct->bits[i];
        append_bytes(out, &s->a[0], sizeof(Torus32) * n);
        append_bytes(out, &s->b, sizeof(Torus32));
        append_bytes(out, &s->current_variance, sizeof(double));
    }
    return out;
}

static std::vector<uint8_t> serialize_lwe(const LweSample* s, const LweParams* params) {
    std::vector<uint8_t> out;
    int32_t n = params->n;
    append_bytes(out, &n, sizeof(n));
    append_bytes(out, &s->a[0], sizeof(Torus32) * n);
    append_bytes(out, &s->b, sizeof(Torus32));
    append_bytes(out, &s->current_variance, sizeof(double));
    return out;
}

extern "C" void* orhe_backend_setup_bridge(int32_t family, int32_t bit_width) {
    return orhe_rust_setup_pp(family, bit_width);
}

extern "C" void* orhe_backend_setup_pbs_semantic_bridge(int32_t bit_width, int32_t lwe_n) {
    return orhe_rust_setup_pbs_semantic_pp(bit_width, lwe_n);
}

extern "C" void* orhe_backend_setup_signext_semantic_bridge(int32_t bit_width) {
    return orhe_rust_setup_signext_semantic_pp(bit_width);
}

extern "C" void orhe_backend_free_bridge(void* handle) {
    orhe_rust_free_pp(handle);
}

extern "C" int32_t orhe_backend_prove_pbs_bridge(
    void* handle,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    std::vector<uint8_t> x = serialize_ct(x_in);
    std::vector<uint8_t> y = serialize_ct(y_out);
    return orhe_rust_prove_pbs(
        handle,
        x.data(), (uint64_t)x.size(),
        y.data(), (uint64_t)y.size(),
        out_ptr, out_len
    );
}

extern "C" int32_t orhe_backend_verify_pbs_bridge(
    void* handle,
    const ORHECiphertext* x_in,
    const ORHECiphertext* y_out,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    std::vector<uint8_t> x = serialize_ct(x_in);
    std::vector<uint8_t> y = serialize_ct(y_out);
    return orhe_rust_verify_pbs(
        handle,
        x.data(), (uint64_t)x.size(),
        y.data(), (uint64_t)y.size(),
        proof_ptr, proof_len
    );
}

extern "C" int32_t orhe_backend_prove_signext_bridge(
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
) {
    static bool dumped_once = false;
    std::vector<uint8_t> d = serialize_ct(diff);
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    if (debug_compare_enabled() && !dumped_once) {
        dumped_once = true;
        debug_dump_bytes("prove_signext serialized diff", d);
        debug_dump_bytes("prove_signext serialized claimed checkpoint", s);
        if (trace_ptr && trace_len > 0) {
            std::vector<uint8_t> t(trace_ptr, trace_ptr + (size_t) trace_len);
            debug_dump_bytes("prove_signext serialized subtraction trace", t);
        }
        if (witness_ptr && witness_len > 0) {
            std::vector<uint8_t> w(witness_ptr, witness_ptr + (size_t) witness_len);
            debug_dump_bytes("prove_signext boolean witness bytes", w);
        }
    }
    int32_t ok = orhe_rust_prove_signext(
        handle,
        d.data(), (uint64_t)d.size(),
        s.data(), (uint64_t)s.size(),
        trace_ptr, trace_len,
        witness_ptr, witness_len,
        out_ptr, out_len
    );
    if (debug_compare_enabled() && ok && out_ptr && out_len && *out_ptr && *out_len) {
        debug_dump_proof("prove_signext proof bytes", *out_ptr, *out_len);
    }
    return ok;
}

extern "C" int32_t orhe_backend_verify_signext_bridge(
    void* handle,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const uint8_t* trace_ptr,
    uint64_t trace_len,
    const TFheGateBootstrappingParameterSet* params,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    static bool dumped_once = false;
    std::vector<uint8_t> d = serialize_ct(diff);
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    if (debug_compare_enabled() && !dumped_once) {
        dumped_once = true;
        debug_dump_bytes("verify_signext serialized diff", d);
        debug_dump_bytes("verify_signext serialized claimed checkpoint", s);
        if (trace_ptr && trace_len > 0) {
            std::vector<uint8_t> t(trace_ptr, trace_ptr + (size_t) trace_len);
            debug_dump_bytes("verify_signext serialized subtraction trace", t);
        }
        debug_dump_proof("verify_signext proof bytes", proof_ptr, proof_len);
    }
    return orhe_rust_verify_signext(
        handle,
        d.data(), (uint64_t)d.size(),
        s.data(), (uint64_t)s.size(),
        trace_ptr, trace_len,
        proof_ptr, proof_len
    );
}

extern "C" int32_t orhe_backend_prove_pbs_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return orhe_rust_prove_pbs_semantic(
        handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        out_ptr,
        out_len
    );
}

extern "C" int32_t orhe_backend_verify_pbs_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return orhe_rust_verify_pbs_semantic(
        handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        proof_ptr,
        proof_len
    );
}

extern "C" int32_t orhe_backend_prove_ks_bridge(
    void* handle,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    std::vector<uint8_t> ub = serialize_lwe(u, params->in_out_params);
    return orhe_rust_prove_ks(
        handle,
        s.data(), (uint64_t)s.size(),
        ub.data(), (uint64_t)ub.size(),
        out_ptr, out_len
    );
}

extern "C" int32_t orhe_backend_prove_signext_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    return orhe_rust_prove_signext_semantic(
        handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        out_ptr,
        out_len
    );
}

extern "C" int32_t orhe_backend_verify_signext_semantic_bridge(
    void* handle,
    const uint8_t* stmt_ptr,
    uint64_t stmt_len,
    const uint8_t* wit_ptr,
    uint64_t wit_len,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    return orhe_rust_verify_signext_semantic(
        handle,
        stmt_ptr,
        stmt_len,
        wit_ptr,
        wit_len,
        proof_ptr,
        proof_len
    );
}

extern "C" int32_t orhe_backend_verify_ks_bridge(
    void* handle,
    const LweSample* c_sgn,
    const LweSample* u,
    const TFheGateBootstrappingParameterSet* params,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    std::vector<uint8_t> ub = serialize_lwe(u, params->in_out_params);
    return orhe_rust_verify_ks(
        handle,
        s.data(), (uint64_t)s.size(),
        ub.data(), (uint64_t)ub.size(),
        proof_ptr, proof_len
    );
}

extern "C" void orhe_backend_free_buffer_bridge(uint8_t* ptr, uint64_t len) {
    orhe_rust_free_buffer(ptr, len);
}
