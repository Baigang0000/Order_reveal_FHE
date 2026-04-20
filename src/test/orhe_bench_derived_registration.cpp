#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "orhe.h"
#include "orhe_metrics.h"

struct FamilySpec {
    const char* name;
    int arity;
    int num_linear_stages;
    int num_pbs;
    int pbs_depth;
};

struct DerivedBenchConfig {
    int32_t runs;
    uint32_t seed;
    std::string output_path;
    bool validate;
    bool run_all;
    const FamilySpec* member;
};

struct DerivedRunSample {
    uint64_t tfhe_eval_us;
    uint64_t prover_us;
    uint64_t verifier_us;
    uint64_t end_to_end_online_us;
    uint64_t proof_size_bytes;
    uint64_t ciphertext_size_bytes;
    uint64_t metadata_size_bytes;
    uint64_t total_online_comm_bytes;
    uint64_t server_state_bytes;
    uint64_t gate_state_bytes;
};

struct Stats {
    double mean;
    double stddev;
};

struct LookupTables {
    std::vector<uint32_t> t2;
    std::vector<uint32_t> t3;
    std::vector<uint32_t> t4;
    std::vector<uint32_t> t5;
};

struct EvalArtifacts {
    ORHECircuitTrace* trace;
    std::vector<ORHECiphertext*> wires;
    std::vector<ORHECiphertext*> owned;
    ORHECiphertext* claimed;
    uint64_t tfhe_eval_us;
    uint64_t prover_us;
};

static const FamilySpec kFamilies[] = {
    {"f1", 1, 1, 1, 1},
    {"f2", 1, 2, 1, 1},
    {"f3", 1, 2, 2, 2},
    {"f4", 2, 1, 1, 1},
    {"f5", 2, 2, 1, 1},
    {"f6", 2, 3, 2, 2},
};

[[maybe_unused]] static void init_empty_proof(ORHEProof* proof) {
    proof->family = ORHE_PROOF_FAMILY_NONE;
    proof->blob = NULL;
    proof->blob_len = 0;
    proof->owns_backend_buffer = 0;
}

static uint32_t modulus_q(const ORHEParams* params) {
    return (uint32_t) (1u << params->bit_width);
}

static uint32_t wrap_mod_q(uint64_t value, uint32_t q) {
    return (uint32_t) (value % (uint64_t) q);
}

// The derived-registration benchmark uses affine maps over the current
// bit-sliced ciphertext representation, so the "linear" stages are affine over
// bits rather than integer-linear over Z/qZ.
static uint32_t clear_l1(uint32_t x, uint32_t q) { return wrap_mod_q(x ^ 0x3cu, q); }
static uint32_t clear_l2(uint32_t x, uint32_t q) { return wrap_mod_q(x ^ 0xa5u, q); }
static uint32_t clear_l3(uint32_t x, uint32_t q) { return wrap_mod_q(x ^ 0x5au, q); }
static uint32_t clear_l4(uint32_t x, uint32_t y, uint32_t q) { return wrap_mod_q((x ^ y) ^ 0x96u, q); }
static uint32_t clear_l5(uint32_t x, uint32_t q) { return wrap_mod_q(x ^ 0x0fu, q); }
static uint32_t clear_l6(uint32_t x, uint32_t q) { return wrap_mod_q(x ^ 0x33u, q); }

static uint32_t clear_t2(uint32_t m, uint32_t q) { return wrap_mod_q(m & 0x0fu, q); }
static uint32_t clear_t3(uint32_t m, uint32_t q) { return wrap_mod_q((q - 1u) ^ m, q); }
static uint32_t clear_t4(uint32_t m, uint32_t q) {
    return wrap_mod_q(m & 0x03u, q);
}
static uint32_t clear_t5(uint32_t m, uint32_t q) { return wrap_mod_q((m >> 7) & 1u, q); }

static uint32_t clear_f1(uint32_t x, uint32_t q) {
    return clear_t2(clear_l1(x, q), q);
}

static uint32_t clear_f2(uint32_t x, uint32_t q) {
    return clear_l2(clear_t2(clear_l1(x, q), q), q);
}

static uint32_t clear_f3(uint32_t x, uint32_t q) {
    return clear_t3(clear_l3(clear_t2(clear_l1(x, q), q), q), q);
}

static uint32_t clear_f4(uint32_t x, uint32_t y, uint32_t q) {
    return clear_t4(clear_l4(x, y, q), q);
}

static uint32_t clear_f5(uint32_t x, uint32_t y, uint32_t q) {
    return clear_l5(clear_t4(clear_l4(x, y, q), q), q);
}

static uint32_t clear_f6(uint32_t x, uint32_t y, uint32_t q) {
    const uint32_t z0 = clear_t4(clear_l4(x, y, q), q);
    const uint32_t z1 = clear_l5(z0, q);
    const uint32_t z2 = clear_t5(z1, q);
    return clear_l6(z2, q);
}

static std::vector<uint32_t> build_lut(uint32_t q, uint32_t (*fn)(uint32_t, uint32_t)) {
    std::vector<uint32_t> lut((size_t) q, 0);
    for (uint32_t i = 0; i < q; ++i) {
        lut[(size_t) i] = fn(i, q);
    }
    return lut;
}

static LookupTables build_lookup_tables(uint32_t q) {
    LookupTables out;
    out.t2 = build_lut(q, clear_t2);
    out.t3 = build_lut(q, clear_t3);
    out.t4 = build_lut(q, clear_t4);
    out.t5 = build_lut(q, clear_t5);
    return out;
}

static bool parse_positive_int32(const char* text, int32_t* out) {
    char* end = NULL;
    long value = std::strtol(text, &end, 10);
    if (!text || !*text || !end || *end != '\0') return false;
    if (value <= 0 || value > 1000000L) return false;
    *out = (int32_t) value;
    return true;
}

static bool parse_uint32_arg(const char* text, uint32_t* out) {
    char* end = NULL;
    unsigned long value = std::strtoul(text, &end, 10);
    if (!text || !*text || !end || *end != '\0') return false;
    if (value > 0xffffffffUL) return false;
    *out = (uint32_t) value;
    return true;
}

static const FamilySpec* find_family(const char* name) {
    for (size_t i = 0; i < sizeof(kFamilies) / sizeof(kFamilies[0]); ++i) {
        if (std::strcmp(kFamilies[i].name, name) == 0) {
            return &kFamilies[i];
        }
    }
    return NULL;
}

static bool parse_args(int argc, char** argv, DerivedBenchConfig* cfg) {
    cfg->runs = 5;
    cfg->seed = 1;
    cfg->output_path.clear();
    cfg->validate = false;
    cfg->run_all = true;
    cfg->member = NULL;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            if (!parse_positive_int32(argv[++i], &cfg->runs)) return false;
            continue;
        }
        if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (!parse_uint32_arg(argv[++i], &cfg->seed)) return false;
            continue;
        }
        if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            cfg->output_path = argv[++i];
            continue;
        }
        if (std::strcmp(argv[i], "--member") == 0 && i + 1 < argc) {
            cfg->member = find_family(argv[++i]);
            if (!cfg->member) return false;
            cfg->run_all = false;
            continue;
        }
        if (std::strcmp(argv[i], "--all") == 0) {
            cfg->run_all = true;
            cfg->member = NULL;
            continue;
        }
        if (std::strcmp(argv[i], "--validate") == 0) {
            cfg->validate = true;
            continue;
        }
        return false;
    }

    return true;
}

static void destroy_eval_artifacts(EvalArtifacts* artifacts) {
    if (!artifacts) return;
    for (size_t i = 0; i < artifacts->owned.size(); ++i) {
        orhe_delete_ciphertext(artifacts->owned[i]);
    }
    artifacts->owned.clear();
    artifacts->wires.clear();
    if (artifacts->trace) {
        orhe_trace_delete(artifacts->trace);
        artifacts->trace = NULL;
    }
    artifacts->claimed = NULL;
    artifacts->tfhe_eval_us = 0;
    artifacts->prover_us = 0;
}

static bool register_base_checked(
    ORHEHandleTable* table,
    uint64_t handle,
    ORHECiphertext* ct,
    const ORHEKeySet* ks,
    ORHEMetrics* metrics
) {
    ORHEAuthSignature sig;
    orhe_auth_sign(&sig, handle, ct, &ks->auth_sk);
    return orhe_register_base_with_metrics(table, handle, ct, &sig, ks, metrics) == 1;
}

static int append_input_wire(EvalArtifacts* artifacts, ORHECiphertext* input) {
    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_INPUT;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = -1;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) return -1;
    artifacts->wires.push_back(input);
    return op.dst_wire;
}

static int append_const_wire(
    EvalArtifacts* artifacts,
    uint32_t value,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    for (int32_t bit = 0; bit < ks->params.bit_width; ++bit) {
        const int32_t value_bit = ((value >> bit) & 1u) ? 1 : 0;
        bootsCONSTANT(&out->bits[bit], value_bit, &ks->data_sk->cloud);
    }
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_CONST;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = -1;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = (int32_t) value;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }

    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

static int append_xor_wire(
    EvalArtifacts* artifacts,
    int src0_wire,
    int src1_wire,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_xor(out, artifacts->wires[(size_t) src0_wire], artifacts->wires[(size_t) src1_wire], &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_XOR;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src0_wire;
    op.src1_wire = src1_wire;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }

    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

[[maybe_unused]] static int append_and_wire(
    EvalArtifacts* artifacts,
    int src0_wire,
    int src1_wire,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_and(out, artifacts->wires[(size_t) src0_wire], artifacts->wires[(size_t) src1_wire], &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_AND;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src0_wire;
    op.src1_wire = src1_wire;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }
    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

[[maybe_unused]] static int append_not_wire(
    EvalArtifacts* artifacts,
    int src_wire,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_not(out, artifacts->wires[(size_t) src_wire], &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_NOT;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src_wire;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }

    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

[[maybe_unused]] static int append_add_wire(
    EvalArtifacts* artifacts,
    int src0_wire,
    int src1_wire,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_add(out, artifacts->wires[(size_t) src0_wire], artifacts->wires[(size_t) src1_wire], &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_ADD;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src0_wire;
    op.src1_wire = src1_wire;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }

    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

[[maybe_unused]] static int append_sub_wire(
    EvalArtifacts* artifacts,
    int src0_wire,
    int src1_wire,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_sub(out, artifacts->wires[(size_t) src0_wire], artifacts->wires[(size_t) src1_wire], &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHEProof proof;
    init_empty_proof(&proof);
    ORHETimer prove_timer;
    orhe_timer_start(&prove_timer);
    orhe_proof_prove_sub_partial(
        &proof,
        ks->sub_pp,
        artifacts->wires[(size_t) src0_wire],
        artifacts->wires[(size_t) src1_wire],
        out,
        ks
    );
    artifacts->prover_us += orhe_timer_elapsed_us(&prove_timer);
    if (proof.family != ORHE_PROOF_FAMILY_SUB) {
        orhe_proof_clear(&proof);
        orhe_delete_ciphertext(out);
        return -1;
    }

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_SUB;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src0_wire;
    op.src1_wire = src1_wire;
    op.src2_wire = -1;
    op.aux_value = 0;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_proof_clear(&proof);
        orhe_delete_ciphertext(out);
        return -1;
    }
    if (orhe_trace_append_sub_checkpoint(artifacts->trace, &proof) != 1) {
        orhe_proof_clear(&proof);
        orhe_delete_ciphertext(out);
        return -1;
    }

    orhe_proof_clear(&proof);
    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

[[maybe_unused]] static int append_shr_wire(
    EvalArtifacts* artifacts,
    int src_wire,
    int shift,
    const ORHEKeySet* ks
) {
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer timer;
    orhe_timer_start(&timer);
    orhe_shr(out, artifacts->wires[(size_t) src_wire], shift, &ks->data_sk->cloud);
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&timer);

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_SHR;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src_wire;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = shift;
    if (orhe_trace_append_op(artifacts->trace, op) != 1) {
        orhe_delete_ciphertext(out);
        return -1;
    }

    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

static int append_pbs_wire(
    EvalArtifacts* artifacts,
    int src_wire,
    int relation,
    const ORHEKeySet* ks
) {
    const ORHEProofPP* prove_pp =
        (relation == ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE ||
         relation == ORHE_PBS_RELATION_T3_BITWISE_NOT ||
         relation == ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS ||
         relation == ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB) ? ks->reg_pbs_pp : ks->pbs_pp;
    ORHECiphertext* out = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
    ORHETimer eval_timer;
    orhe_timer_start(&eval_timer);
    if (!orhe_eval_allowed_pbs_relation(out, artifacts->wires[(size_t) src_wire], relation, ks)) {
        orhe_delete_ciphertext(out);
        return -1;
    }
    artifacts->tfhe_eval_us += orhe_timer_elapsed_us(&eval_timer);

    ORHEProof proof;
    init_empty_proof(&proof);
    ORHETimer prove_timer;
    orhe_timer_start(&prove_timer);
    orhe_proof_prove_pbs_relation(
        &proof,
        prove_pp,
        relation,
        artifacts->wires[(size_t) src_wire],
        out,
        ks
    );
    artifacts->prover_us += orhe_timer_elapsed_us(&prove_timer);
    if (proof.family != ORHE_PROOF_FAMILY_PBS) {
        orhe_proof_clear(&proof);
        orhe_delete_ciphertext(out);
        return -1;
    }

    ORHETraceOp op;
    op.kind = ORHE_TRACE_OP_PBS;
    op.dst_wire = (int32_t) artifacts->wires.size();
    op.src0_wire = src_wire;
    op.src1_wire = -1;
    op.src2_wire = -1;
    op.aux_value = relation;
    if (orhe_trace_append_op(artifacts->trace, op) != 1 ||
        orhe_trace_append_pbs_checkpoint(artifacts->trace, artifacts->wires[(size_t) src_wire], out, &proof) != 1) {
        orhe_proof_clear(&proof);
        orhe_delete_ciphertext(out);
        return -1;
    }

    orhe_proof_clear(&proof);
    artifacts->owned.push_back(out);
    artifacts->wires.push_back(out);
    if (orhe_trace_record_wire(artifacts->trace, op.dst_wire, out) != 1) return -1;
    return op.dst_wire;
}

static bool build_member_trace(
    const FamilySpec* spec,
    const std::vector<ORHECiphertext*>& inputs,
    const LookupTables* tables,
    const ORHEKeySet* ks,
    EvalArtifacts* out
) {
    (void) tables;
    out->trace = orhe_trace_new(ks->params.bit_width);
    out->wires.clear();
    out->owned.clear();
    out->claimed = NULL;
    out->tfhe_eval_us = 0;
    out->prover_us = 0;

    const int x = append_input_wire(out, inputs[0]);
    const int y = (spec->arity == 2) ? append_input_wire(out, inputs[1]) : -1;
    if (x < 0 || (spec->arity == 2 && y < 0)) return false;

    int final_wire = -1;

    if (std::strcmp(spec->name, "f1") == 0) {
        const int c1 = append_const_wire(out, 0x3cu, ks);
        const int l1 = append_xor_wire(out, x, c1, ks);
        final_wire = append_pbs_wire(out, l1, ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE, ks);
    } else if (std::strcmp(spec->name, "f2") == 0) {
        const int c1 = append_const_wire(out, 0x3cu, ks);
        const int l1 = append_xor_wire(out, x, c1, ks);
        const int p0 = append_pbs_wire(out, l1, ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE, ks);
        const int c2 = append_const_wire(out, 0xa5u, ks);
        final_wire = append_xor_wire(out, p0, c2, ks);
    } else if (std::strcmp(spec->name, "f3") == 0) {
        const int c1 = append_const_wire(out, 0x3cu, ks);
        const int l1 = append_xor_wire(out, x, c1, ks);
        const int p0 = append_pbs_wire(out, l1, ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE, ks);
        const int c3 = append_const_wire(out, 0x5au, ks);
        const int l3 = append_xor_wire(out, p0, c3, ks);
        final_wire = append_pbs_wire(out, l3, ORHE_PBS_RELATION_T3_BITWISE_NOT, ks);
    } else if (std::strcmp(spec->name, "f4") == 0) {
        const int xy = append_xor_wire(out, x, y, ks);
        const int c4 = append_const_wire(out, 0x96u, ks);
        const int l4 = append_xor_wire(out, xy, c4, ks);
        final_wire = append_pbs_wire(out, l4, ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS, ks);
    } else if (std::strcmp(spec->name, "f5") == 0) {
        const int xy = append_xor_wire(out, x, y, ks);
        const int c4 = append_const_wire(out, 0x96u, ks);
        const int l4 = append_xor_wire(out, xy, c4, ks);
        const int p0 = append_pbs_wire(out, l4, ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS, ks);
        const int c5 = append_const_wire(out, 0x0fu, ks);
        final_wire = append_xor_wire(out, p0, c5, ks);
    } else if (std::strcmp(spec->name, "f6") == 0) {
        const int xy = append_xor_wire(out, x, y, ks);
        const int c4 = append_const_wire(out, 0x96u, ks);
        const int l4 = append_xor_wire(out, xy, c4, ks);
        const int p0 = append_pbs_wire(out, l4, ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS, ks);
        const int c5 = append_const_wire(out, 0x0fu, ks);
        const int l5 = append_xor_wire(out, p0, c5, ks);
        const int p1 = append_pbs_wire(out, l5, ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB, ks);
        const int c6 = append_const_wire(out, 0x33u, ks);
        final_wire = append_xor_wire(out, p1, c6, ks);
    }

    if (final_wire < 0) return false;
    out->trace->final_wire = final_wire;
    out->claimed = out->wires[(size_t) final_wire];
    return true;
}

static uint32_t clear_member_output(const FamilySpec* spec, uint32_t x, uint32_t y, uint32_t q) {
    if (std::strcmp(spec->name, "f1") == 0) return clear_f1(x, q);
    if (std::strcmp(spec->name, "f2") == 0) return clear_f2(x, q);
    if (std::strcmp(spec->name, "f3") == 0) return clear_f3(x, q);
    if (std::strcmp(spec->name, "f4") == 0) return clear_f4(x, y, q);
    if (std::strcmp(spec->name, "f5") == 0) return clear_f5(x, y, q);
    if (std::strcmp(spec->name, "f6") == 0) return clear_f6(x, y, q);
    return 0;
}

static bool run_one_member(
    const FamilySpec* spec,
    uint32_t x_plain,
    uint32_t y_plain,
    const LookupTables* tables,
    const ORHEKeySet* ks,
    DerivedRunSample* out_sample,
    bool check_clear_output
) {
    ORHEHandleTable table;
    orhe_init_table(&table);

    ORHEMetrics reg_metrics;
    orhe_metrics_reset(&reg_metrics);

    std::vector<ORHECiphertext*> inputs;
    std::vector<uint64_t> handles;
    inputs.reserve((size_t) spec->arity);
    handles.reserve((size_t) spec->arity);

    bool ok = true;
    for (int i = 0; i < spec->arity; ++i) {
        const uint32_t value = (i == 0) ? x_plain : y_plain;
        ORHECiphertext* ct = orhe_new_ciphertext(ks->params.bit_width, ks->tfhe_params);
        orhe_sym_encrypt_uint(ct, value, ks);
        inputs.push_back(ct);
        const uint64_t handle = 1000ULL + (uint64_t) i;
        handles.push_back(handle);
        if (!register_base_checked(&table, handle, ct, ks, &reg_metrics)) {
            ok = false;
            break;
        }
    }

    EvalArtifacts artifacts;
    artifacts.trace = NULL;
    artifacts.claimed = NULL;
    artifacts.tfhe_eval_us = 0;
    artifacts.prover_us = 0;

    if (ok) {
        ok = build_member_trace(spec, inputs, tables, ks, &artifacts);
        if (!ok) {
            std::fprintf(stderr, "build_member_trace failed for %s\n", spec->name);
        }
    }

    if (ok && check_clear_output) {
        const uint32_t expected = clear_member_output(spec, x_plain, y_plain, modulus_q(&ks->params));
        const uint32_t actual = orhe_sym_decrypt_uint(artifacts.claimed, ks);
        if (expected != actual) {
            std::fprintf(stderr, "validation mismatch for %s: expected=%u actual=%u\n", spec->name, expected, actual);
            ok = false;
        }
    }

    if (ok) {
        const uint64_t derived_handle = 9000ULL;
        if (orhe_register_derived_with_metrics(
                &table,
                derived_handle,
                handles.data(),
                (int32_t) handles.size(),
                artifacts.claimed,
                artifacts.trace,
                ks,
                &reg_metrics) != 1) {
            std::fprintf(
                stderr,
                "register_derived failed for %s: %s\n",
                spec->name,
                orhe_register_derived_last_error()
            );
            ok = false;
        }
    }

    if (ok && out_sample) {
        out_sample->tfhe_eval_us = artifacts.tfhe_eval_us;
        out_sample->prover_us = artifacts.prover_us;
        out_sample->verifier_us = reg_metrics.verifier_us;
        out_sample->end_to_end_online_us = reg_metrics.end_to_end_online_us + artifacts.tfhe_eval_us + artifacts.prover_us;
        out_sample->proof_size_bytes = reg_metrics.proof_size_bytes;
        out_sample->ciphertext_size_bytes = reg_metrics.ciphertext_size_bytes;
        out_sample->metadata_size_bytes = reg_metrics.metadata_size_bytes;
        out_sample->total_online_comm_bytes = reg_metrics.total_online_comm_bytes;
        out_sample->server_state_bytes = reg_metrics.server_state_bytes;
        out_sample->gate_state_bytes = reg_metrics.gate_state_bytes;
    }

    orhe_free_table(&table);
    destroy_eval_artifacts(&artifacts);
    for (size_t i = 0; i < inputs.size(); ++i) {
        orhe_delete_ciphertext(inputs[i]);
    }

    return ok;
}

static Stats compute_stats(const std::vector<double>& values) {
    Stats out;
    out.mean = 0.0;
    out.stddev = 0.0;
    if (values.empty()) return out;

    for (size_t i = 0; i < values.size(); ++i) out.mean += values[i];
    out.mean /= (double) values.size();

    if (values.size() > 1) {
        double sum_sq = 0.0;
        for (size_t i = 0; i < values.size(); ++i) {
            const double delta = values[i] - out.mean;
            sum_sq += delta * delta;
        }
        out.stddev = std::sqrt(sum_sq / (double) (values.size() - 1));
    }
    return out;
}

static void print_summary_csv_header(FILE* out) {
    // Field meanings:
    // - tfhe_eval_us: execution time for the evaluated derived function itself, excluding proof generation.
    // - prover_us: time spent generating any proof material required by the
    //   current secure derived-registration path.
    // - verifier_us: time spent by existing derived registration verification.
    // - end_to_end_online_us: base registration + derived ciphertext evaluation + proof generation + derived registration.
    // - byte counts come from existing base/derived registration metric helpers and therefore reflect the current ORHE protocol messages/state.
    std::fprintf(
        out,
        "family_member,arity,num_linear_stages,num_pbs,pbs_depth,num_runs,"
        "tfhe_eval_us_mean,tfhe_eval_us_std,"
        "prover_us_mean,prover_us_std,"
        "verifier_us_mean,verifier_us_std,"
        "end_to_end_online_us_mean,end_to_end_online_us_std,"
        "proof_size_bytes_mean,proof_size_bytes_std,"
        "ciphertext_size_bytes_mean,ciphertext_size_bytes_std,"
        "metadata_size_bytes_mean,metadata_size_bytes_std,"
        "total_online_comm_bytes_mean,total_online_comm_bytes_std,"
        "server_state_bytes_mean,server_state_bytes_std,"
        "gate_state_bytes_mean,gate_state_bytes_std\n"
    );
}

static void print_summary_csv_row(
    FILE* out,
    const FamilySpec* spec,
    int32_t runs,
    const std::vector<DerivedRunSample>& samples
) {
    std::vector<double> tfhe_eval_us;
    std::vector<double> prover_us;
    std::vector<double> verifier_us;
    std::vector<double> end_to_end_online_us;
    std::vector<double> proof_size_bytes;
    std::vector<double> ciphertext_size_bytes;
    std::vector<double> metadata_size_bytes;
    std::vector<double> total_online_comm_bytes;
    std::vector<double> server_state_bytes;
    std::vector<double> gate_state_bytes;

    tfhe_eval_us.reserve(samples.size());
    prover_us.reserve(samples.size());
    verifier_us.reserve(samples.size());
    end_to_end_online_us.reserve(samples.size());
    proof_size_bytes.reserve(samples.size());
    ciphertext_size_bytes.reserve(samples.size());
    metadata_size_bytes.reserve(samples.size());
    total_online_comm_bytes.reserve(samples.size());
    server_state_bytes.reserve(samples.size());
    gate_state_bytes.reserve(samples.size());

    for (size_t i = 0; i < samples.size(); ++i) {
        tfhe_eval_us.push_back((double) samples[i].tfhe_eval_us);
        prover_us.push_back((double) samples[i].prover_us);
        verifier_us.push_back((double) samples[i].verifier_us);
        end_to_end_online_us.push_back((double) samples[i].end_to_end_online_us);
        proof_size_bytes.push_back((double) samples[i].proof_size_bytes);
        ciphertext_size_bytes.push_back((double) samples[i].ciphertext_size_bytes);
        metadata_size_bytes.push_back((double) samples[i].metadata_size_bytes);
        total_online_comm_bytes.push_back((double) samples[i].total_online_comm_bytes);
        server_state_bytes.push_back((double) samples[i].server_state_bytes);
        gate_state_bytes.push_back((double) samples[i].gate_state_bytes);
    }

    const Stats tfhe_stats = compute_stats(tfhe_eval_us);
    const Stats prover_stats = compute_stats(prover_us);
    const Stats verifier_stats = compute_stats(verifier_us);
    const Stats e2e_stats = compute_stats(end_to_end_online_us);
    const Stats proof_stats = compute_stats(proof_size_bytes);
    const Stats ct_stats = compute_stats(ciphertext_size_bytes);
    const Stats metadata_stats = compute_stats(metadata_size_bytes);
    const Stats comm_stats = compute_stats(total_online_comm_bytes);
    const Stats server_state_stats = compute_stats(server_state_bytes);
    const Stats gate_state_stats = compute_stats(gate_state_bytes);

    std::fprintf(
        out,
        "%s,%d,%d,%d,%d,%d,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f,"
        "%.3f,%.3f\n",
        spec->name,
        spec->arity,
        spec->num_linear_stages,
        spec->num_pbs,
        spec->pbs_depth,
        runs,
        tfhe_stats.mean, tfhe_stats.stddev,
        prover_stats.mean, prover_stats.stddev,
        verifier_stats.mean, verifier_stats.stddev,
        e2e_stats.mean, e2e_stats.stddev,
        proof_stats.mean, proof_stats.stddev,
        ct_stats.mean, ct_stats.stddev,
        metadata_stats.mean, metadata_stats.stddev,
        comm_stats.mean, comm_stats.stddev,
        server_state_stats.mean, server_state_stats.stddev,
        gate_state_stats.mean, gate_state_stats.stddev
    );
}

static bool validate_members(
    const DerivedBenchConfig* cfg,
    const LookupTables* tables,
    const ORHEKeySet* ks
) {
    const uint32_t x_fixed = 37u;
    const uint32_t y_fixed = 91u;

    if (!cfg->run_all) {
        return run_one_member(cfg->member, x_fixed, y_fixed, tables, ks, NULL, true);
    }

    for (size_t i = 0; i < sizeof(kFamilies) / sizeof(kFamilies[0]); ++i) {
        if (!run_one_member(&kFamilies[i], x_fixed, y_fixed, tables, ks, NULL, true)) {
            return false;
        }
    }

    return true;
}

int main(int argc, char** argv) {
    DerivedBenchConfig cfg;
    if (!parse_args(argc, argv, &cfg)) {
        std::fprintf(
            stderr,
            "usage: %s [--runs N] [--seed S] [--output PATH] [--member f1|f2|f3|f4|f5|f6] [--all] [--validate]\n",
            argv[0]
        );
        return 1;
    }

    FILE* out = stdout;
    if (!cfg.output_path.empty()) {
        out = std::fopen(cfg.output_path.c_str(), "w");
        if (!out) {
            std::fprintf(stderr, "failed to open output csv: %s\n", cfg.output_path.c_str());
            return 1;
        }
    }

    ORHEParams params;
    params.bit_width = 8;
    params.domain_min = 0;
    params.domain_max = 255;

    ORHEKeySet* ks = orhe_new_keyset(110, &params);
    const uint32_t q = modulus_q(&params);
    const LookupTables tables = build_lookup_tables(q);

    if (cfg.validate && !validate_members(&cfg, &tables, ks)) {
        std::fprintf(stderr, "validation failed\n");
        orhe_delete_keyset(ks);
        if (out != stdout) std::fclose(out);
        return 1;
    }

    std::mt19937 rng(cfg.seed);
    std::uniform_int_distribution<uint32_t> dist(0u, q - 1u);

    print_summary_csv_header(out);

    const size_t family_count = sizeof(kFamilies) / sizeof(kFamilies[0]);
    for (size_t i = 0; i < family_count; ++i) {
        const FamilySpec* spec = &kFamilies[i];
        if (!cfg.run_all && spec != cfg.member) continue;

        std::vector<DerivedRunSample> samples;
        samples.reserve((size_t) cfg.runs);

        for (int32_t run = 0; run < cfg.runs; ++run) {
            const uint32_t x_plain = dist(rng);
            const uint32_t y_plain = dist(rng);

            DerivedRunSample sample;
            if (!run_one_member(spec, x_plain, y_plain, &tables, ks, &sample, false)) {
                std::fprintf(stderr, "benchmark run failed for %s (run %d)\n", spec->name, (int) (run + 1));
                orhe_delete_keyset(ks);
                if (out != stdout) std::fclose(out);
                return 1;
            }
            samples.push_back(sample);
        }

        print_summary_csv_row(out, spec, cfg.runs, samples);
    }

    orhe_delete_keyset(ks);
    if (out != stdout) std::fclose(out);
    return 0;
}
