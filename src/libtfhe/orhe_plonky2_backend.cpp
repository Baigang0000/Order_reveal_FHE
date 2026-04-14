#include "orhe_plonky2_backend.h"

#include <vector>
#include <cstring>

extern "C" {

// Rust FFI exports
void* orhe_rust_setup_pp(int32_t family, int32_t bit_width);
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

int32_t orhe_rust_prove_signext(
    void* handle,
    const uint8_t* d_ptr, uint64_t d_len,
    const uint8_t* s_ptr, uint64_t s_len,
    uint8_t** out_ptr, uint64_t* out_len
);

int32_t orhe_rust_verify_signext(
    void* handle,
    const uint8_t* d_ptr, uint64_t d_len,
    const uint8_t* s_ptr, uint64_t s_len,
    const uint8_t* proof_ptr, uint64_t proof_len
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
    const TFheGateBootstrappingParameterSet* params,
    uint8_t** out_ptr,
    uint64_t* out_len
) {
    std::vector<uint8_t> d = serialize_ct(diff);
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    return orhe_rust_prove_signext(
        handle,
        d.data(), (uint64_t)d.size(),
        s.data(), (uint64_t)s.size(),
        out_ptr, out_len
    );
}

extern "C" int32_t orhe_backend_verify_signext_bridge(
    void* handle,
    const ORHECiphertext* diff,
    const LweSample* c_sgn,
    const TFheGateBootstrappingParameterSet* params,
    const uint8_t* proof_ptr,
    uint64_t proof_len
) {
    std::vector<uint8_t> d = serialize_ct(diff);
    std::vector<uint8_t> s = serialize_lwe(c_sgn, params->in_out_params);
    return orhe_rust_verify_signext(
        handle,
        d.data(), (uint64_t)d.size(),
        s.data(), (uint64_t)s.size(),
        proof_ptr, proof_len
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
