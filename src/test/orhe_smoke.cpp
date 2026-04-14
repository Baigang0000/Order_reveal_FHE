#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "orhe.h"
#include "orhe_metrics.h"

static void print_result(const char* label, int ok) {
    std::printf("%s: %s\n", label, ok ? "PASS" : "FAIL");
}

static void init_empty_proof(ORHEProof* p) {
    p->family = ORHE_PROOF_FAMILY_NONE;
    p->blob = NULL;
    p->blob_len = 0;
    p->owns_backend_buffer = 0;
}

static void deep_copy_proof(ORHEProof* dst, const ORHEProof* src) {
    init_empty_proof(dst);
    dst->family = src->family;
    dst->blob_len = src->blob_len;
    dst->owns_backend_buffer = 0;

    if (src->blob && src->blob_len > 0) {
        dst->blob = (uint8_t*) std::malloc((size_t) src->blob_len);
        std::memcpy(dst->blob, src->blob, (size_t) src->blob_len);
    }
}

int main() {
    std::srand(12345);

    ORHEParams p;
    p.bit_width = 8;
    p.domain_min = 0;
    p.domain_max = 255;

    ORHEKeySet* ks = orhe_new_keyset(110, &p);

    ORHEHandleTable H;
    orhe_init_table(&H);

    ORHEMetrics m_base_a, m_base_b, m_dup_handle, m_bad_sig;
    ORHEMetrics m_compare_prove, m_compare_verify, m_compare_bad_sgn, m_compare_bad_ks;
    ORHEMetrics m_regder_good, m_regder_bad;
    ORHEMetrics m_compare_derived_prove, m_compare_derived_verify;

    orhe_metrics_reset(&m_base_a);
    orhe_metrics_reset(&m_base_b);
    orhe_metrics_reset(&m_dup_handle);
    orhe_metrics_reset(&m_bad_sig);
    orhe_metrics_reset(&m_compare_prove);
    orhe_metrics_reset(&m_compare_verify);
    orhe_metrics_reset(&m_compare_bad_sgn);
    orhe_metrics_reset(&m_compare_bad_ks);
    orhe_metrics_reset(&m_regder_good);
    orhe_metrics_reset(&m_regder_bad);
    orhe_metrics_reset(&m_compare_derived_prove);
    orhe_metrics_reset(&m_compare_derived_verify);

    // --------------------------------------------------
    // Base registration test
    // --------------------------------------------------
    ORHECiphertext* a = orhe_new_ciphertext(8, ks->tfhe_params);
    ORHECiphertext* b = orhe_new_ciphertext(8, ks->tfhe_params);

    // Keep the larger values
    orhe_sym_encrypt_uint(a, 200, ks);
    orhe_sym_encrypt_uint(b, 150, ks);

    ORHEAuthSignature sig_a;
    ORHEAuthSignature sig_b;
    orhe_auth_sign(&sig_a, 1001, a, &ks->auth_sk);
    orhe_auth_sign(&sig_b, 1002, b, &ks->auth_sk);

    int reg_a = orhe_register_base_with_metrics(&H, 1001, a, &sig_a, ks, &m_base_a);
    int reg_b = orhe_register_base_with_metrics(&H, 1002, b, &sig_b, ks, &m_base_b);

    print_result("RegisterBase(a)", reg_a == 1);
    print_result("RegisterBase(b)", reg_b == 1);

    // Duplicate handle should fail
    ORHECiphertext* dup = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(dup, 7, ks);
    ORHEAuthSignature sig_dup;
    orhe_auth_sign(&sig_dup, 1001, dup, &ks->auth_sk);
    int reg_dup = orhe_register_base_with_metrics(&H, 1001, dup, &sig_dup, ks, &m_dup_handle);
    print_result("Duplicate handle rejected", reg_dup == 0);
    orhe_delete_ciphertext(dup);

    // Bad signature should fail
    ORHECiphertext* badsig_ct = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(badsig_ct, 9, ks);
    ORHEAuthSignature badsig;
    orhe_auth_sign(&badsig, 1003, badsig_ct, &ks->auth_sk);
    badsig.bytes[0] ^= 0x01;
    int reg_badsig = orhe_register_base_with_metrics(&H, 1003, badsig_ct, &badsig, ks, &m_bad_sig);
    print_result("Bad signature rejected", reg_badsig == 0);
    orhe_delete_ciphertext(badsig_ct);

    // --------------------------------------------------
    // Verified compare test
    // --------------------------------------------------
    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->tfhe_params->in_out_params);

    ORHEProof pi_sgn;
    ORHEProof pi_ks;
    init_empty_proof(&pi_sgn);
    init_empty_proof(&pi_ks);

    int prove_ok = orhe_compare_server_prove_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi_sgn, &pi_ks, ks, &m_compare_prove
    );
    print_result("Server compare proof generation", prove_ok == 1);

    int cmp = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi_sgn, &pi_ks, ks, &m_compare_verify
    );
    std::printf("Verified compare result for 200 < 150: %d\n", cmp);
    print_result("Verified compare accepts valid proof", cmp == 0);

    // Tamper with sign proof
    ORHEProof pi_sgn_bad;
    deep_copy_proof(&pi_sgn_bad, &pi_sgn);
    if (pi_sgn_bad.blob && pi_sgn_bad.blob_len > 0) {
        pi_sgn_bad.blob[0] ^= 0x01;
    }

    int cmp_bad_sgn = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi_sgn_bad, &pi_ks, ks, &m_compare_bad_sgn
    );
    print_result("Tampered sign proof rejected", cmp_bad_sgn == -1);

    // Tamper with ks proof
    ORHEProof pi_ks_bad;
    deep_copy_proof(&pi_ks_bad, &pi_ks);
    if (pi_ks_bad.blob && pi_ks_bad.blob_len > 0) {
        pi_ks_bad.blob[0] ^= 0x01;
    }

    int cmp_bad_ks = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi_sgn, &pi_ks_bad, ks, &m_compare_bad_ks
    );
    print_result("Tampered ks proof rejected", cmp_bad_ks == -1);

    // --------------------------------------------------
    // RegisterDer test: simple SUB trace with no PBS checkpoints
    // --------------------------------------------------
    ORHECiphertext* claimed_sub = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sub(claimed_sub, a, b, &ks->data_sk->cloud);

    ORHECircuitTrace* tr = orhe_trace_new(8);

    ORHETraceOp op0;
    op0.kind = ORHE_TRACE_OP_INPUT;
    op0.dst_wire = 0;
    op0.src0_wire = -1;
    op0.src1_wire = -1;
    op0.src2_wire = -1;
    op0.aux_value = 0;
    orhe_trace_append_op(tr, op0);

    ORHETraceOp op1;
    op1.kind = ORHE_TRACE_OP_INPUT;
    op1.dst_wire = 1;
    op1.src0_wire = -1;
    op1.src1_wire = -1;
    op1.src2_wire = -1;
    op1.aux_value = 0;
    orhe_trace_append_op(tr, op1);

    ORHETraceOp op2;
    op2.kind = ORHE_TRACE_OP_SUB;
    op2.dst_wire = 2;
    op2.src0_wire = 0;
    op2.src1_wire = 1;
    op2.src2_wire = -1;
    op2.aux_value = 0;
    orhe_trace_append_op(tr, op2);

    tr->final_wire = 2;

    uint64_t src_handles[2];
    src_handles[0] = 1001;
    src_handles[1] = 1002;

    int reg_der_ok = orhe_register_derived_with_metrics(
        &H, 2001, src_handles, 2, claimed_sub, tr, ks, &m_regder_good
    );
    print_result("RegisterDer valid trace accepted", reg_der_ok == 1);

    // RegisterDer tamper: wrong claimed output
    ORHECiphertext* wrong_claim = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(wrong_claim, 42, ks);

    int reg_der_bad = orhe_register_derived_with_metrics(
        &H, 2002, src_handles, 2, wrong_claim, tr, ks, &m_regder_bad
    );
    print_result("RegisterDer wrong output rejected", reg_der_bad == 0);
    orhe_delete_ciphertext(wrong_claim);

    // --------------------------------------------------
    // Compare using derived handle against itself
    // --------------------------------------------------
    LweSample* c_sgn2 = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u2 = new_LweSample(ks->tfhe_params->in_out_params);

    ORHEProof pi_sgn2;
    ORHEProof pi_ks2;
    init_empty_proof(&pi_sgn2);
    init_empty_proof(&pi_ks2);

    int prove_ok2 = orhe_compare_server_prove_with_metrics(
        2001, 2001, &H, c_sgn2, u2, &pi_sgn2, &pi_ks2, ks, &m_compare_derived_prove
    );
    print_result("Server compare proof generation on derived handle", prove_ok2 == 1);

    int cmp2 = orhe_gate_compare_verified_with_metrics(
        2001, 2001, &H, c_sgn2, u2, &pi_sgn2, &pi_ks2, ks, &m_compare_derived_verify
    );
    std::printf("Verified compare result for derived value < itself: %d\n", cmp2);
    print_result("Derived handle compare works", cmp2 == 0);

    // --------------------------------------------------
    // Metrics output
    // --------------------------------------------------
    std::puts("\nCSV metrics:");
    orhe_metrics_print_csv_header(stdout);
    orhe_metrics_print_csv_row(stdout, "register_base_a", &m_base_a);
    orhe_metrics_print_csv_row(stdout, "register_base_b", &m_base_b);
    orhe_metrics_print_csv_row(stdout, "register_base_duplicate_handle", &m_dup_handle);
    orhe_metrics_print_csv_row(stdout, "register_base_bad_signature", &m_bad_sig);
    orhe_metrics_print_csv_row(stdout, "compare_prove", &m_compare_prove);
    orhe_metrics_print_csv_row(stdout, "compare_verify", &m_compare_verify);
    orhe_metrics_print_csv_row(stdout, "compare_verify_bad_sign_proof", &m_compare_bad_sgn);
    orhe_metrics_print_csv_row(stdout, "compare_verify_bad_ks_proof", &m_compare_bad_ks);
    orhe_metrics_print_csv_row(stdout, "register_derived_valid", &m_regder_good);
    orhe_metrics_print_csv_row(stdout, "register_derived_wrong_output", &m_regder_bad);
    orhe_metrics_print_csv_row(stdout, "compare_derived_prove", &m_compare_derived_prove);
    orhe_metrics_print_csv_row(stdout, "compare_derived_verify", &m_compare_derived_verify);

    // --------------------------------------------------
    // Cleanup
    // --------------------------------------------------
    orhe_proof_clear(&pi_sgn);
    orhe_proof_clear(&pi_ks);
    orhe_proof_clear(&pi_sgn_bad);
    orhe_proof_clear(&pi_ks_bad);
    orhe_proof_clear(&pi_sgn2);
    orhe_proof_clear(&pi_ks2);

    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    delete_gate_bootstrapping_ciphertext(c_sgn2);
    delete_LweSample(u2);

    orhe_trace_delete(tr);

    // a, b, claimed_sub are owned by the handle table entries after successful registration.
    orhe_free_table(&H);
    orhe_delete_keyset(ks);

    return 0;
}
