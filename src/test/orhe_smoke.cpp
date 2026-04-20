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

static void copy_bytes(ORHEBytes* dst, const ORHEBytes* src) {
    dst->ptr = NULL;
    dst->len = 0;
    if (!src || !src->ptr || src->len == 0) return;
    dst->ptr = (uint8_t*) std::malloc((size_t) src->len);
    dst->len = src->len;
    std::memcpy(dst->ptr, src->ptr, (size_t) src->len);
}

static void deep_copy_statement(ORHESignExtPublicStatement* dst, const ORHESignExtPublicStatement* src) {
    std::memset(dst, 0, sizeof(*dst));
    dst->version = src->version;
    copy_bytes(&dst->d_ser, &src->d_ser);
    copy_bytes(&dst->pbs_input_ser, &src->pbs_input_ser);
    copy_bytes(&dst->c_sgn_ser, &src->c_sgn_ser);
    dst->relation_id = src->relation_id;
    std::memcpy(&dst->tfhe_ctx_id, &src->tfhe_ctx_id, sizeof(dst->tfhe_ctx_id));
}

static void deep_copy_witness(ORHESignExtWitness* dst, const ORHESignExtWitness* src) {
    std::memset(dst, 0, sizeof(*dst));
    dst->version = src->version;
    copy_bytes(&dst->pbs_input_ser, &src->pbs_input_ser);
    copy_bytes(&dst->pre_ks_lwe_ser, &src->pre_ks_lwe_ser);

    dst->b1.version = src->b1.version;
    copy_bytes(&dst->b1.pbs_input_ser, &src->b1.pbs_input_ser);
    copy_bytes(&dst->b1.accum_init_tlwe_ser, &src->b1.accum_init_tlwe_ser);
    std::memcpy(dst->b1.ctx_root, src->b1.ctx_root, sizeof(dst->b1.ctx_root));

    dst->b2.version = src->b2.version;
    copy_bytes(&dst->b2.pbs_input_ser, &src->b2.pbs_input_ser);
    copy_bytes(&dst->b2.accum_init_tlwe_ser, &src->b2.accum_init_tlwe_ser);
    copy_bytes(&dst->b2.blind_rot_accum_tlwe_ser, &src->b2.blind_rot_accum_tlwe_ser);
    std::memcpy(dst->b2.ctx_root, src->b2.ctx_root, sizeof(dst->b2.ctx_root));

    dst->b3.version = src->b3.version;
    copy_bytes(&dst->b3.blind_rot_accum_tlwe_ser, &src->b3.blind_rot_accum_tlwe_ser);
    copy_bytes(&dst->b3.pre_ks_lwe_ser, &src->b3.pre_ks_lwe_ser);
    std::memcpy(dst->b3.ctx_root, src->b3.ctx_root, sizeof(dst->b3.ctx_root));

    dst->b4.version = src->b4.version;
    copy_bytes(&dst->b4.pre_ks_lwe_ser, &src->b4.pre_ks_lwe_ser);
    copy_bytes(&dst->b4.c_sgn_ser, &src->b4.c_sgn_ser);
    std::memcpy(dst->b4.pbs_ks_id, src->b4.pbs_ks_id, sizeof(dst->b4.pbs_ks_id));
    std::memcpy(dst->b4.ctx_root, src->b4.ctx_root, sizeof(dst->b4.ctx_root));
}

static void tamper_serialized_sample(ORHEBytes* bytes) {
    if (!bytes || !bytes->ptr || bytes->len == 0) return;
    size_t off = (bytes->len > 16) ? 16 : (size_t) (bytes->len - 1);
    bytes->ptr[off] ^= 0x01;
}

static void build_mask_low_bits_output(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    int keep_bits,
    const ORHEKeySet* ks
) {
    for (int i = 0; i < in->nbits; ++i) {
        if (i < keep_bits) {
            bootsCOPY(&out->bits[i], &in->bits[i], &ks->data_sk->cloud);
        } else {
            bootsCONSTANT(&out->bits[i], 0, &ks->data_sk->cloud);
        }
    }
}

static void build_extract_msb_to_lsb_output(
    ORHECiphertext* out,
    const ORHECiphertext* in,
    const ORHEKeySet* ks
) {
    bootsCOPY(&out->bits[0], &in->bits[in->nbits - 1], &ks->data_sk->cloud);
    for (int i = 1; i < in->nbits; ++i) {
        bootsCONSTANT(&out->bits[i], 0, &ks->data_sk->cloud);
    }
}

static int run_semantic_signext_case(
    const ORHEProofPP* pp,
    const ORHESignExtPublicStatement* stmt,
    const ORHESignExtWitness* wit,
    const ORHEKeySet* ks
) {
    ORHEProof pi;
    init_empty_proof(&pi);
    orhe_proof_prove_signext_semantic(&pi, pp, stmt, wit);
    if (pi.family != ORHE_PROOF_FAMILY_SIGNEXT) {
        orhe_proof_clear(&pi);
        return 0;
    }
    int ok = orhe_proof_verify_signext_semantic(pp, stmt, &pi, ks) ? 1 : 0;
    orhe_proof_clear(&pi);
    return ok;
}

static int register_base_literal(
    ORHEHandleTable* H,
    uint64_t handle,
    uint32_t value,
    const ORHEKeySet* ks
) {
    ORHECiphertext* ct = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    orhe_sym_encrypt_uint(ct, value, ks);

    ORHEAuthSignature sig;
    orhe_auth_sign(&sig, handle, ct, &ks->auth_sk);

    if (!orhe_register_base(H, handle, ct, &sig, ks)) {
        orhe_delete_ciphertext(ct);
        return 0;
    }

    return 1;
}

static int run_compare_case(
    const char* label,
    uint64_t left_handle,
    uint64_t right_handle,
    int expected_sigma,
    const ORHEHandleTable* H,
    const ORHEKeySet* ks
) {
    LweSample* c_sgn = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u = new_LweSample(ks->cmp_sk->params);

    ORHEProof pi;
    init_empty_proof(&pi);

    int prove_ok = orhe_compare_server_prove(left_handle, right_handle, H, c_sgn, u, &pi, ks);
    int sigma = (prove_ok == 1)
        ? orhe_gate_compare_verified(left_handle, right_handle, H, c_sgn, u, &pi, ks)
        : -1;

    std::printf("%s result: %d\n", label, sigma);
    print_result(label, prove_ok == 1 && sigma == expected_sigma);

    orhe_proof_clear(&pi);
    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    return sigma;
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
    ORHEMetrics m_compare_prove, m_compare_verify, m_compare_bad_proof, m_compare_bad_u;
    ORHEMetrics m_regder_good, m_regder_bad;
    ORHEMetrics m_compare_derived_prove, m_compare_derived_verify;

    orhe_metrics_reset(&m_base_a);
    orhe_metrics_reset(&m_base_b);
    orhe_metrics_reset(&m_dup_handle);
    orhe_metrics_reset(&m_bad_sig);
    orhe_metrics_reset(&m_compare_prove);
    orhe_metrics_reset(&m_compare_verify);
    orhe_metrics_reset(&m_compare_bad_proof);
    orhe_metrics_reset(&m_compare_bad_u);
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
    LweSample* u = new_LweSample(ks->cmp_sk->params);

    ORHEProof pi;
    init_empty_proof(&pi);

    int prove_ok = orhe_compare_server_prove_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi, ks, &m_compare_prove
    );
    print_result("Server compare trace-backed proof generation", prove_ok == 1);

    int cmp = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi, ks, &m_compare_verify
    );
    std::printf("Verified compare result for 200 < 150: %d\n", cmp);
    print_result("Verified compare accepts valid trace-backed proof", cmp == 0);

    LweKeySwitchKey* saved_cmp_ks = ks->data_to_cmp_ks;
    ks->data_to_cmp_ks = NULL;
    int cmp_without_cmpks = orhe_gate_compare_verified(
        1001, 1002, &H, c_sgn, u, &pi, ks
    );
    ks->data_to_cmp_ks = saved_cmp_ks;
    print_result("Verified compare works without final KS key material", cmp_without_cmpks == 0);

    // --------------------------------------------------
    // Explicit partial semantic SignExt path retained as a focused unit smoke:
    // B1 accumulator init and B3 extraction are proven in Plonky2,
    // while B2 blind rotation and B4 internal KS are verifier-replayed.
    // --------------------------------------------------
    ORHECiphertext* d_sem = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sub(d_sem, a, b, &ks->data_sk->cloud);

    ORHEProofPP* signext_sem_pp = orhe_proof_setup_signext_semantic(ks->params.bit_width);
    ORHESignExtPublicStatement sem_stmt;
    ORHESignExtWitness sem_wit;
    std::memset(&sem_stmt, 0, sizeof(sem_stmt));
    std::memset(&sem_wit, 0, sizeof(sem_wit));

    ORHEProof sem_pi;
    init_empty_proof(&sem_pi);

    int sem_stmt_ok = orhe_signext_build_public_statement(&sem_stmt, d_sem, c_sgn, ks);
    int sem_wit_ok = orhe_signext_build_witness(&sem_wit, d_sem, c_sgn, ks);
    orhe_proof_prove_signext_semantic(&sem_pi, signext_sem_pp, &sem_stmt, &sem_wit);
    int sem_verify_ok = orhe_proof_verify_signext_semantic(signext_sem_pp, &sem_stmt, &sem_pi, ks);

    print_result(
        "Partial semantic SignExt(B1/B3 proof; B2/B4 replay) path",
        sem_stmt_ok == 1 && sem_wit_ok == 1 && sem_pi.family == ORHE_PROOF_FAMILY_SIGNEXT && sem_verify_ok == 1
    );

    ORHESignExtWitness wit_bad_accum;
    std::memset(&wit_bad_accum, 0, sizeof(wit_bad_accum));
    deep_copy_witness(&wit_bad_accum, &sem_wit);
    tamper_serialized_sample(&wit_bad_accum.b1.accum_init_tlwe_ser);
    tamper_serialized_sample(&wit_bad_accum.b2.accum_init_tlwe_ser);
    print_result(
        "Partial semantic SignExt wrong accumulator init rejected",
        run_semantic_signext_case(signext_sem_pp, &sem_stmt, &wit_bad_accum, ks) == 0
    );
    orhe_signext_witness_clear(&wit_bad_accum);

    ORHESignExtWitness wit_bad_blind_rot;
    std::memset(&wit_bad_blind_rot, 0, sizeof(wit_bad_blind_rot));
    deep_copy_witness(&wit_bad_blind_rot, &sem_wit);
    tamper_serialized_sample(&wit_bad_blind_rot.b2.blind_rot_accum_tlwe_ser);
    tamper_serialized_sample(&wit_bad_blind_rot.b3.blind_rot_accum_tlwe_ser);
    print_result(
        "Partial semantic SignExt wrong blind rotation state rejected",
        run_semantic_signext_case(signext_sem_pp, &sem_stmt, &wit_bad_blind_rot, ks) == 0
    );
    orhe_signext_witness_clear(&wit_bad_blind_rot);

    ORHESignExtWitness wit_bad_extract;
    std::memset(&wit_bad_extract, 0, sizeof(wit_bad_extract));
    deep_copy_witness(&wit_bad_extract, &sem_wit);
    tamper_serialized_sample(&wit_bad_extract.pre_ks_lwe_ser);
    tamper_serialized_sample(&wit_bad_extract.b3.pre_ks_lwe_ser);
    tamper_serialized_sample(&wit_bad_extract.b4.pre_ks_lwe_ser);
    print_result(
        "Partial semantic SignExt wrong extracted value rejected",
        run_semantic_signext_case(signext_sem_pp, &sem_stmt, &wit_bad_extract, ks) == 0
    );
    orhe_signext_witness_clear(&wit_bad_extract);

    ORHESignExtPublicStatement stmt_bad_ks;
    ORHESignExtWitness wit_bad_ks;
    std::memset(&stmt_bad_ks, 0, sizeof(stmt_bad_ks));
    std::memset(&wit_bad_ks, 0, sizeof(wit_bad_ks));
    deep_copy_statement(&stmt_bad_ks, &sem_stmt);
    deep_copy_witness(&wit_bad_ks, &sem_wit);
    tamper_serialized_sample(&stmt_bad_ks.c_sgn_ser);
    tamper_serialized_sample(&wit_bad_ks.b4.c_sgn_ser);
    print_result(
        "Partial semantic SignExt wrong internal KS output rejected",
        run_semantic_signext_case(signext_sem_pp, &stmt_bad_ks, &wit_bad_ks, ks) == 0
    );
    orhe_signext_public_statement_clear(&stmt_bad_ks);
    orhe_signext_witness_clear(&wit_bad_ks);

    ORHESignExtPublicStatement stmt_bad_relation;
    std::memset(&stmt_bad_relation, 0, sizeof(stmt_bad_relation));
    deep_copy_statement(&stmt_bad_relation, &sem_stmt);
    stmt_bad_relation.relation_id ^= 1u;
    print_result(
        "Partial semantic SignExt wrong relation id rejected",
        run_semantic_signext_case(signext_sem_pp, &stmt_bad_relation, &sem_wit, ks) == 0
    );
    orhe_signext_public_statement_clear(&stmt_bad_relation);

    ORHEKeySet* ks_replay = orhe_new_keyset(110, &p);
    int sem_replay_ok = orhe_proof_verify_signext_semantic(signext_sem_pp, &sem_stmt, &sem_pi, ks_replay);
    print_result("Partial semantic SignExt cross-context replay rejected", sem_replay_ok == 0);
    orhe_delete_keyset(ks_replay);

    // Tamper with the PBS proof
    ORHEProof pi_bad;
    deep_copy_proof(&pi_bad, &pi);
    if (pi_bad.blob && pi_bad.blob_len > 0) {
        pi_bad.blob[0] ^= 0x01;
    }

    int cmp_bad_proof = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u, &pi_bad, ks, &m_compare_bad_proof
    );
    print_result("Tampered compare proof bundle rejected", cmp_bad_proof == -1);

    // Tamper with the separately proved final KS output
    LweSample* u_bad = new_LweSample(ks->cmp_sk->params);
    lweCopy(u_bad, u, ks->cmp_sk->params);
    u_bad->b += 1;

    int cmp_bad_u = orhe_gate_compare_verified_with_metrics(
        1001, 1002, &H, c_sgn, u_bad, &pi, ks, &m_compare_bad_u
    );
    print_result("Tampered final KS output rejected", cmp_bad_u == -1);

    orhe_proof_clear(&sem_pi);
    orhe_signext_public_statement_clear(&sem_stmt);
    orhe_signext_witness_clear(&sem_wit);
    orhe_proof_pp_delete(signext_sem_pp);
    orhe_delete_ciphertext(d_sem);

    // --------------------------------------------------
    // Derived-registration PBS semantic checkpoint: T3 bitwise NOT only
    // --------------------------------------------------
    ORHECiphertext* not_a = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_not(not_a, a, &ks->data_sk->cloud);

    ORHEProof t3_pi;
    init_empty_proof(&t3_pi);
    orhe_proof_prove_pbs_relation(
        &t3_pi,
        ks->reg_pbs_pp,
        ORHE_PBS_RELATION_T3_BITWISE_NOT,
        a,
        not_a,
        ks
    );
    print_result(
        "PBS semantic T3 proof generation",
        t3_pi.family == ORHE_PROOF_FAMILY_PBS
    );
    print_result(
        "PBS semantic T3 verification",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T3_BITWISE_NOT,
            a,
            not_a,
            &t3_pi,
            ks
        ) == 1
    );
    print_result(
        "PBS semantic T3 wrong relation id rejected",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS,
            a,
            not_a,
            &t3_pi,
            ks
        ) == 0
    );
    ORHEKeySet* ks_t3_replay = orhe_new_keyset(110, &p);
    print_result(
        "PBS semantic T3 cross-context replay rejected",
        orhe_proof_verify_pbs_relation(
            ks_t3_replay->reg_pbs_pp,
            ORHE_PBS_RELATION_T3_BITWISE_NOT,
            a,
            not_a,
            &t3_pi,
            ks_t3_replay
        ) == 0
    );
    orhe_delete_keyset(ks_t3_replay);
    ORHEProof t3_pi_bad;
    deep_copy_proof(&t3_pi_bad, &t3_pi);
    if (t3_pi_bad.blob && t3_pi_bad.blob_len > 0) {
        t3_pi_bad.blob[0] ^= 0x01;
    }
    print_result(
        "PBS semantic T3 tampered proof rejected",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T3_BITWISE_NOT,
            a,
            not_a,
            &t3_pi_bad,
            ks
        ) == 0
    );
    orhe_proof_clear(&t3_pi_bad);

    ORHECiphertext* forged_not = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(forged_not, 91, ks);
    ORHEProof forged_t3_pi;
    init_empty_proof(&forged_t3_pi);
    orhe_proof_prove_pbs_relation(
        &forged_t3_pi,
        ks->reg_pbs_pp,
        ORHE_PBS_RELATION_T3_BITWISE_NOT,
        a,
        forged_not,
        ks
    );
    print_result(
        "PBS semantic T3 forged output rejected",
        forged_t3_pi.family != ORHE_PROOF_FAMILY_PBS
    );
    orhe_proof_clear(&forged_t3_pi);
    orhe_delete_ciphertext(forged_not);

    ORHECircuitTrace* t3_tr = orhe_trace_new(8);
    ORHETraceOp t3_in;
    t3_in.kind = ORHE_TRACE_OP_INPUT;
    t3_in.dst_wire = 0;
    t3_in.src0_wire = -1;
    t3_in.src1_wire = -1;
    t3_in.src2_wire = -1;
    t3_in.aux_value = 0;
    orhe_trace_append_op(t3_tr, t3_in);
    ORHETraceOp t3_op;
    t3_op.kind = ORHE_TRACE_OP_PBS;
    t3_op.dst_wire = 1;
    t3_op.src0_wire = 0;
    t3_op.src1_wire = -1;
    t3_op.src2_wire = -1;
    t3_op.aux_value = ORHE_PBS_RELATION_T3_BITWISE_NOT;
    orhe_trace_append_op(t3_tr, t3_op);
    orhe_trace_append_pbs_checkpoint(t3_tr, a, not_a, &t3_pi);
    t3_tr->final_wire = 1;

    uint64_t t3_src_handles[1];
    t3_src_handles[0] = 1001;
    int reg_der_t3_ok = orhe_register_derived(
        &H, 2005, t3_src_handles, 1, not_a, t3_tr, ks
    );
    print_result("RegisterDer semantic T3 trace accepted", reg_der_t3_ok == 1);

    ORHECircuitTrace* t3_bad_rel_tr = orhe_trace_new(8);
    orhe_trace_append_op(t3_bad_rel_tr, t3_in);
    t3_op.aux_value = ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS;
    orhe_trace_append_op(t3_bad_rel_tr, t3_op);
    orhe_trace_append_pbs_checkpoint(t3_bad_rel_tr, a, not_a, &t3_pi);
    t3_bad_rel_tr->final_wire = 1;
    int reg_der_t3_bad_rel = orhe_register_derived(
        &H, 2006, t3_src_handles, 1, not_a, t3_bad_rel_tr, ks
    );
    print_result("RegisterDer semantic T3 wrong relation rejected", reg_der_t3_bad_rel == 0);

    orhe_trace_delete(t3_bad_rel_tr);
    orhe_trace_delete(t3_tr);
    orhe_proof_clear(&t3_pi);
    if (!reg_der_t3_ok) {
        orhe_delete_ciphertext(not_a);
    }

    ORHECiphertext* t2_out = orhe_new_ciphertext(8, ks->tfhe_params);
    build_mask_low_bits_output(t2_out, a, 4, ks);
    ORHEProof t2_pi;
    init_empty_proof(&t2_pi);
    orhe_proof_prove_pbs_relation(
        &t2_pi,
        ks->reg_pbs_pp,
        ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE,
        a,
        t2_out,
        ks
    );
    print_result("PBS semantic T2 proof generation", t2_pi.family == ORHE_PROOF_FAMILY_PBS);
    print_result(
        "PBS semantic T2 verification",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE,
            a,
            t2_out,
            &t2_pi,
            ks
        ) == 1
    );
    ORHECircuitTrace* t2_tr = orhe_trace_new(8);
    orhe_trace_append_op(t2_tr, t3_in);
    t3_op.aux_value = ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE;
    orhe_trace_append_op(t2_tr, t3_op);
    orhe_trace_append_pbs_checkpoint(t2_tr, a, t2_out, &t2_pi);
    t2_tr->final_wire = 1;
    int reg_der_t2_ok = orhe_register_derived(&H, 2007, t3_src_handles, 1, t2_out, t2_tr, ks);
    print_result("RegisterDer semantic T2 trace accepted", reg_der_t2_ok == 1);
    orhe_trace_delete(t2_tr);
    orhe_proof_clear(&t2_pi);
    if (!reg_der_t2_ok) orhe_delete_ciphertext(t2_out);

    ORHECiphertext* t4_out = orhe_new_ciphertext(8, ks->tfhe_params);
    build_mask_low_bits_output(t4_out, a, 2, ks);
    ORHEProof t4_pi;
    init_empty_proof(&t4_pi);
    orhe_proof_prove_pbs_relation(
        &t4_pi,
        ks->reg_pbs_pp,
        ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS,
        a,
        t4_out,
        ks
    );
    print_result("PBS semantic T4 proof generation", t4_pi.family == ORHE_PROOF_FAMILY_PBS);
    print_result(
        "PBS semantic T4 verification",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS,
            a,
            t4_out,
            &t4_pi,
            ks
        ) == 1
    );
    ORHECircuitTrace* t4_tr = orhe_trace_new(8);
    orhe_trace_append_op(t4_tr, t3_in);
    t3_op.aux_value = ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS;
    orhe_trace_append_op(t4_tr, t3_op);
    orhe_trace_append_pbs_checkpoint(t4_tr, a, t4_out, &t4_pi);
    t4_tr->final_wire = 1;
    int reg_der_t4_ok = orhe_register_derived(&H, 2008, t3_src_handles, 1, t4_out, t4_tr, ks);
    print_result("RegisterDer semantic T4 trace accepted", reg_der_t4_ok == 1);
    orhe_trace_delete(t4_tr);
    orhe_proof_clear(&t4_pi);
    if (!reg_der_t4_ok) orhe_delete_ciphertext(t4_out);

    ORHECiphertext* t5_out = orhe_new_ciphertext(8, ks->tfhe_params);
    build_extract_msb_to_lsb_output(t5_out, a, ks);
    ORHEProof t5_pi;
    init_empty_proof(&t5_pi);
    orhe_proof_prove_pbs_relation(
        &t5_pi,
        ks->reg_pbs_pp,
        ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB,
        a,
        t5_out,
        ks
    );
    print_result("PBS semantic T5 proof generation", t5_pi.family == ORHE_PROOF_FAMILY_PBS);
    print_result(
        "PBS semantic T5 verification",
        orhe_proof_verify_pbs_relation(
            ks->reg_pbs_pp,
            ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB,
            a,
            t5_out,
            &t5_pi,
            ks
        ) == 1
    );
    ORHECircuitTrace* t5_tr = orhe_trace_new(8);
    orhe_trace_append_op(t5_tr, t3_in);
    t3_op.aux_value = ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB;
    orhe_trace_append_op(t5_tr, t3_op);
    orhe_trace_append_pbs_checkpoint(t5_tr, a, t5_out, &t5_pi);
    t5_tr->final_wire = 1;
    int reg_der_t5_ok = orhe_register_derived(&H, 2009, t3_src_handles, 1, t5_out, t5_tr, ks);
    print_result("RegisterDer semantic T5 trace accepted", reg_der_t5_ok == 1);
    orhe_trace_delete(t5_tr);
    orhe_proof_clear(&t5_pi);
    if (!reg_der_t5_ok) orhe_delete_ciphertext(t5_out);

    // --------------------------------------------------
    // RegisterDer test: simple SUB trace with no PBS checkpoints
    // --------------------------------------------------
    ORHECiphertext* claimed_sub = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sub(claimed_sub, a, b, &ks->data_sk->cloud);
    ORHEProof sub_pi;
    init_empty_proof(&sub_pi);
    orhe_proof_prove_sub_partial(&sub_pi, ks->sub_pp, a, b, claimed_sub, ks);
    print_result("Sub partial proof generation", sub_pi.family == ORHE_PROOF_FAMILY_SUB);
    print_result(
        "Sub partial proof verification",
        orhe_proof_verify_sub_partial(ks->sub_pp, a, b, claimed_sub, &sub_pi, ks) == 1
    );
    ORHEProof sub_pi_tampered = sub_pi;
    if (sub_pi.blob_len > 0) {
        sub_pi_tampered.blob = (uint8_t*) std::malloc((size_t) sub_pi.blob_len);
        std::memcpy(sub_pi_tampered.blob, sub_pi.blob, (size_t) sub_pi.blob_len);
        sub_pi_tampered.owns_backend_buffer = 0;
        sub_pi_tampered.blob[0] ^= 0x01u;
        print_result(
            "Sub partial tampered proof rejected",
            orhe_proof_verify_sub_partial(ks->sub_pp, a, b, claimed_sub, &sub_pi_tampered, ks) == 0
        );
        orhe_proof_clear(&sub_pi_tampered);
    }

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
    orhe_trace_append_sub_checkpoint(tr, &sub_pi);
    orhe_trace_record_wire(tr, 2, claimed_sub);

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

    ORHECircuitTrace* tr_bad_sub = orhe_trace_new(8);
    orhe_trace_append_op(tr_bad_sub, op0);
    orhe_trace_append_op(tr_bad_sub, op1);
    orhe_trace_append_op(tr_bad_sub, op2);
    ORHEProof sub_pi_bad = sub_pi;
    sub_pi_bad.blob = (uint8_t*) std::malloc((size_t) sub_pi.blob_len);
    std::memcpy(sub_pi_bad.blob, sub_pi.blob, (size_t) sub_pi.blob_len);
    sub_pi_bad.owns_backend_buffer = 0;
    if (sub_pi_bad.blob_len > 0) sub_pi_bad.blob[sub_pi_bad.blob_len - 1] ^= 0x80u;
    orhe_trace_append_sub_checkpoint(tr_bad_sub, &sub_pi_bad);
    orhe_trace_record_wire(tr_bad_sub, 2, claimed_sub);
    tr_bad_sub->final_wire = 2;
    ORHECiphertext* bad_sub_claim = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_copy(bad_sub_claim, claimed_sub, &ks->data_sk->cloud);
    int reg_der_bad_sub_proof = orhe_register_derived(
        &H, 2010, src_handles, 2, bad_sub_claim, tr_bad_sub, ks
    );
    print_result("RegisterDer tampered sub proof rejected", reg_der_bad_sub_proof == 0);
    if (!reg_der_bad_sub_proof) orhe_delete_ciphertext(bad_sub_claim);
    orhe_proof_clear(&sub_pi_bad);
    orhe_trace_delete(tr_bad_sub);

    // RegisterDer tamper: missing source handle
    ORHECiphertext* missing_src_claim = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(missing_src_claim, 0, ks);
    uint64_t missing_src_handles[2];
    missing_src_handles[0] = 1001;
    missing_src_handles[1] = 999999;
    int reg_der_missing_src = orhe_register_derived(
        &H, 2003, missing_src_handles, 2, missing_src_claim, tr, ks
    );
    print_result(
        "RegisterDer missing source handle rejected",
        reg_der_missing_src == 0 &&
        std::strcmp(orhe_register_derived_last_error(), "missing_source_handle") == 0
    );
    orhe_delete_ciphertext(missing_src_claim);

    // RegisterDer audit: a forged PBS checkpoint should not be enough to mint
    // an arbitrary fresh ciphertext from a registered source handle.
    ORHECiphertext* fake_pbs_claim = orhe_new_ciphertext(8, ks->tfhe_params);
    orhe_sym_encrypt_uint(fake_pbs_claim, 77, ks);
    ORHEProof fake_pbs_proof;
    init_empty_proof(&fake_pbs_proof);
    orhe_proof_prove_pbs(&fake_pbs_proof, ks->pbs_pp, a, fake_pbs_claim);

    ORHECircuitTrace* fake_pbs_tr = orhe_trace_new(8);
    ORHETraceOp fake_in;
    fake_in.kind = ORHE_TRACE_OP_INPUT;
    fake_in.dst_wire = 0;
    fake_in.src0_wire = -1;
    fake_in.src1_wire = -1;
    fake_in.src2_wire = -1;
    fake_in.aux_value = 0;
    orhe_trace_append_op(fake_pbs_tr, fake_in);

    ORHETraceOp fake_pbs_op;
    fake_pbs_op.kind = ORHE_TRACE_OP_PBS;
    fake_pbs_op.dst_wire = 1;
    fake_pbs_op.src0_wire = 0;
    fake_pbs_op.src1_wire = -1;
    fake_pbs_op.src2_wire = -1;
    fake_pbs_op.aux_value = 0;
    orhe_trace_append_op(fake_pbs_tr, fake_pbs_op);
    orhe_trace_append_pbs_checkpoint(fake_pbs_tr, a, fake_pbs_claim, &fake_pbs_proof);
    fake_pbs_tr->final_wire = 1;

    uint64_t fake_pbs_src_handles[1];
    fake_pbs_src_handles[0] = 1001;
    int reg_der_fake_pbs = orhe_register_derived(
        &H, 2004, fake_pbs_src_handles, 1, fake_pbs_claim, fake_pbs_tr, ks
    );
    print_result("RegisterDer arbitrary PBS output rejected", reg_der_fake_pbs == 0);
    if (!reg_der_fake_pbs) {
        orhe_delete_ciphertext(fake_pbs_claim);
    }
    orhe_proof_clear(&fake_pbs_proof);
    orhe_trace_delete(fake_pbs_tr);

    // --------------------------------------------------
    // Compare using derived handle against itself
    // --------------------------------------------------
    LweSample* c_sgn2 = new_gate_bootstrapping_ciphertext(ks->tfhe_params);
    LweSample* u2 = new_LweSample(ks->cmp_sk->params);

    ORHEProof pi2;
    init_empty_proof(&pi2);

    int prove_ok2 = orhe_compare_server_prove_with_metrics(
        2001, 2001, &H, c_sgn2, u2, &pi2, ks, &m_compare_derived_prove
    );
    print_result("Server compare trace-backed proof generation on derived handle", prove_ok2 == 1);

    int cmp2 = orhe_gate_compare_verified_with_metrics(
        2001, 2001, &H, c_sgn2, u2, &pi2, ks, &m_compare_derived_verify
    );
    std::printf("Verified compare result for derived value < itself: %d\n", cmp2);
    print_result("Derived handle compare works", cmp2 == 0);

    // --------------------------------------------------
    // Additional compare-domain smoke cases
    // --------------------------------------------------
    print_result("Register equality lhs", register_base_literal(&H, 3001, 42, ks) == 1);
    print_result("Register equality rhs", register_base_literal(&H, 3002, 42, ks) == 1);
    run_compare_case("Equality case", 3001, 3002, 0, &H, ks);

    print_result("Register neg/pos lhs", register_base_literal(&H, 3003, 255, ks) == 1);
    print_result("Register neg/pos rhs", register_base_literal(&H, 3004, 1, ks) == 1);
    int neg_vs_pos_sigma = run_compare_case(
        "Negative vs positive inputs",
        3003,
        3004,
        1,
        &H,
        ks
    );

    print_result("Register near-zero lhs", register_base_literal(&H, 3005, 0, ks) == 1);
    print_result("Register near-zero rhs", register_base_literal(&H, 3006, 1, ks) == 1);
    run_compare_case("Near-zero case 0 < 1", 3005, 3006, 1, &H, ks);

    print_result("Register near-zero reverse lhs", register_base_literal(&H, 3007, 1, ks) == 1);
    print_result("Register near-zero reverse rhs", register_base_literal(&H, 3008, 0, ks) == 1);
    run_compare_case("Near-zero case 1 < 0", 3007, 3008, 0, &H, ks);

    print_result("Register boundary lhs", register_base_literal(&H, 3009, 127, ks) == 1);
    print_result("Register boundary rhs", register_base_literal(&H, 3010, 128, ks) == 1);
    run_compare_case("Boundary case 0x7f < 0x80", 3009, 3010, 1, &H, ks);

    print_result("Register boundary wrap lhs", register_base_literal(&H, 3011, 128, ks) == 1);
    print_result("Register boundary wrap rhs", register_base_literal(&H, 3012, 127, ks) == 1);
    run_compare_case("Boundary case 0x80 < 0x7f", 3011, 3012, 0, &H, ks);

    std::printf(
        "SignExt output bit 1 means: %s\n",
        (neg_vs_pos_sigma == 1) ? "negative (lhs < rhs)" : "nonnegative (lhs >= rhs)"
    );
    print_result("SignExt bit 1 means negative", neg_vs_pos_sigma == 1);

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
    orhe_metrics_print_csv_row(stdout, "compare_verify_bad_pbs_proof", &m_compare_bad_proof);
    orhe_metrics_print_csv_row(stdout, "compare_verify_bad_u", &m_compare_bad_u);
    orhe_metrics_print_csv_row(stdout, "register_derived_valid", &m_regder_good);
    orhe_metrics_print_csv_row(stdout, "register_derived_wrong_output", &m_regder_bad);
    orhe_metrics_print_csv_row(stdout, "compare_derived_prove", &m_compare_derived_prove);
    orhe_metrics_print_csv_row(stdout, "compare_derived_verify", &m_compare_derived_verify);

    // --------------------------------------------------
    // Cleanup
    // --------------------------------------------------
    orhe_proof_clear(&pi);
    orhe_proof_clear(&pi_bad);
    orhe_proof_clear(&pi2);

    delete_gate_bootstrapping_ciphertext(c_sgn);
    delete_LweSample(u);
    delete_LweSample(u_bad);
    delete_gate_bootstrapping_ciphertext(c_sgn2);
    delete_LweSample(u2);

    orhe_trace_delete(tr);
    orhe_proof_clear(&sub_pi);

    // a, b, claimed_sub are owned by the handle table entries after successful registration.
    orhe_free_table(&H);
    orhe_delete_keyset(ks);

    return 0;
}
