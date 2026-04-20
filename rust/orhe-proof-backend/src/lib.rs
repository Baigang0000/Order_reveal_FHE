use libc::{c_int, c_uchar, c_ulonglong, c_void};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

mod semantic;

const D: usize = 2;
const STATEMENT_DIGEST_LEN: usize = 32;
const PAIR_PUBLIC_INPUT_COUNT: usize = 2 * STATEMENT_DIGEST_LEN;
const SIGNEXT_PUBLIC_INPUT_COUNT: usize = 3 * STATEMENT_DIGEST_LEN;
const SIGNEXT_SEMANTIC_PUBLIC_INPUT_COUNT: usize = 2 * STATEMENT_DIGEST_LEN;
const PBS_SEMANTIC_PUBLIC_INPUT_COUNT: usize = 2 * STATEMENT_DIGEST_LEN;
const SUB_SEMANTIC_PUBLIC_INPUT_COUNT: usize = 2 * STATEMENT_DIGEST_LEN;
const ORHE_PROOF_FAMILY_PBS: i32 = 1;
const ORHE_PROOF_FAMILY_SIGNEXT: i32 = 2;
const ORHE_PROOF_FAMILY_SUB: i32 = 4;
const ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE: u32 = 2;
const ORHE_PBS_RELATION_T3_BITWISE_NOT: u32 = 3;
const ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS: u32 = 4;
const ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB: u32 = 5;
const ORHE_PBS_SEMANTIC_VERSION: u32 = 1;
const ORHE_PBS_SEMANTIC_KIND_STMT: u32 = 1;
const ORHE_PBS_SEMANTIC_KIND_WIT: u32 = 2;
const ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3: u32 = 1;
const ORHE_SIGNEXT_PARTIAL_BACKEND_VERSION: u32 = 1;
const ORHE_SIGNEXT_SEM_STMT_KIND: u32 = 1;
const ORHE_SIGNEXT_SEM_WIT_KIND: u32 = 2;
const ORHE_SIGNEXT_SEM_N: usize = 1024;
const ORHE_SIGNEXT_MU: i32 = 1 << 29;
const ORHE_FALSE_TORUS_B: u64 = (1u64 << 32) - (ORHE_SIGNEXT_MU as u64);
const ORHE_SUB_PARTIAL_VERSION: u32 = 1;
const ORHE_SUB_PARTIAL_KIND_STMT: u32 = 1;
const ORHE_SUB_PARTIAL_KIND_WIT: u32 = 2;
const ORHE_SUB_RELATION_PARTIAL_RIPPLE: u32 = 1;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

static SIGNEXT_PROVE_DEBUG_COUNT: AtomicUsize = AtomicUsize::new(0);
static SIGNEXT_VERIFY_DEBUG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct SignextTargets {
    lhs_bits: Vec<BoolTarget>,
    rhs_bits: Vec<BoolTarget>,
    b_not_bits: Vec<BoolTarget>,
    xor_ab_bits: Vec<BoolTarget>,
    and_ab_bits: Vec<BoolTarget>,
    and_a_cin_bits: Vec<BoolTarget>,
    and_b_cin_bits: Vec<BoolTarget>,
    carry_or_bits: Vec<BoolTarget>,
    carry_out_bits: Vec<BoolTarget>,
    diff_bits: Vec<BoolTarget>,
    c_sgn_bit: BoolTarget,
}

#[derive(Clone)]
struct SignextSemanticTargets {
    boundary: Target,
    first_positive: BoolTarget,
    prefix_bits: Vec<BoolTarget>,
    accum_zero_poly: Vec<Target>,
    accum_message_poly: Vec<Target>,
    blind_rot_zero_poly: Vec<Target>,
    blind_rot_message_poly: Vec<Target>,
    pre_ks_a: Vec<Target>,
    pre_ks_b: Target,
}

#[derive(Clone)]
struct PbsSemanticTargets {
    relation_id: Target,
    is_t2: BoolTarget,
    is_t3: BoolTarget,
    is_t4: BoolTarget,
    is_t5: BoolTarget,
    x_coeffs: Vec<Target>,
    x_b: Vec<Target>,
    y_coeffs: Vec<Target>,
    y_b: Vec<Target>,
    x_coeff_inv: Vec<Target>,
    x_coeff_nz: Vec<BoolTarget>,
    x_b_inv: Vec<Target>,
    x_b_nz: Vec<BoolTarget>,
}

#[derive(Clone)]
struct SubSemanticTargets {
    lhs_bits: Vec<BoolTarget>,
    rhs_bits: Vec<BoolTarget>,
    b_not_bits: Vec<BoolTarget>,
    xor_ab_bits: Vec<BoolTarget>,
    and_ab_bits: Vec<BoolTarget>,
    and_a_cin_bits: Vec<BoolTarget>,
    and_b_cin_bits: Vec<BoolTarget>,
    carry_or_bits: Vec<BoolTarget>,
    carry_out_bits: Vec<BoolTarget>,
    diff_bits: Vec<BoolTarget>,
}

struct SignextWitness {
    lhs_bits: Vec<bool>,
    rhs_bits: Vec<bool>,
    b_not_bits: Vec<bool>,
    xor_ab_bits: Vec<bool>,
    and_ab_bits: Vec<bool>,
    and_a_cin_bits: Vec<bool>,
    and_b_cin_bits: Vec<bool>,
    carry_or_bits: Vec<bool>,
    carry_out_bits: Vec<bool>,
    diff_bits: Vec<bool>,
    c_sgn_bit: bool,
}

struct SignextSemanticStatement {
    relation_id: u32,
}

struct SignextSemanticWitness {
    n: usize,
    boundary: usize,
    first_positive: bool,
    accum_zero_poly: Vec<i32>,
    accum_message_poly: Vec<i32>,
    blind_rot_zero_poly: Vec<i32>,
    blind_rot_message_poly: Vec<i32>,
    pre_ks_a: Vec<i32>,
    pre_ks_b: i32,
}

struct PbsSemanticStatement {
    relation_id: u32,
}

struct SubSemanticStatement {
    relation_id: u32,
}

struct PbsSemanticWitness {
    relation_id: u32,
    nbits: usize,
    lwe_n: usize,
    x_coeffs: Vec<u32>,
    x_b: Vec<u32>,
    y_coeffs: Vec<u32>,
    y_b: Vec<u32>,
}

struct SubSemanticWitness {
    bit_width: usize,
    lhs_bits: Vec<bool>,
    rhs_bits: Vec<bool>,
    b_not_bits: Vec<bool>,
    xor_ab_bits: Vec<bool>,
    and_ab_bits: Vec<bool>,
    and_a_cin_bits: Vec<bool>,
    and_b_cin_bits: Vec<bool>,
    carry_or_bits: Vec<bool>,
    carry_out_bits: Vec<bool>,
    diff_bits: Vec<bool>,
}

struct BackendPP {
    family: i32,
    bit_width: i32,
    lwe_n: i32,
    data: CircuitData<F, C, D>,
    public_targets: Vec<Target>,
    signext_targets: Option<SignextTargets>,
    signext_semantic_targets: Option<SignextSemanticTargets>,
    pbs_semantic_targets: Option<PbsSemanticTargets>,
    sub_semantic_targets: Option<SubSemanticTargets>,
}

unsafe fn as_slice<'a>(ptr: *const u8, len: u64) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len as usize)
    }
}

fn debug_compare_enabled() -> bool {
    matches!(std::env::var("ORHE_DEBUG_COMPARE"), Ok(v) if v == "1")
}

fn debug_compare_full_enabled() -> bool {
    matches!(std::env::var("ORHE_DEBUG_COMPARE_FULL"), Ok(v) if v == "1")
}

fn should_debug_once(counter: &AtomicUsize) -> bool {
    debug_compare_enabled() && counter.fetch_add(1, Ordering::Relaxed) == 0
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut acc = 0xcbf29ce484222325u64;
    for &b in bytes {
        acc ^= b as u64;
        acc = acc.wrapping_mul(0x100000001b3u64);
    }
    acc
}

fn hex_preview(bytes: &[u8]) -> String {
    if debug_compare_full_enabled() || bytes.len() <= 64 {
        return bytes.iter().map(|b| format!("{:02x}", b)).collect();
    }

    let head: String = bytes[..64].iter().map(|b| format!("{:02x}", b)).collect();
    let tail: String = bytes[bytes.len() - 16..]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("{head}...{tail}")
}

fn debug_dump_bytes(label: &str, bytes: &[u8]) {
    eprintln!(
        "[rust][compare-debug] {label}: len={} fnv64={:016x} hex={}",
        bytes.len(),
        fnv1a64(bytes),
        hex_preview(bytes)
    );
}

fn debug_dump_public_inputs(label: &str, public_inputs: &[F]) {
    let ints: Vec<u64> = public_inputs.iter().map(|f| f.to_canonical_u64()).collect();
    let bytes: Vec<u8> = ints.iter().map(|&v| v as u8).collect();
    eprintln!(
        "[rust][compare-debug] {label}: count={} fnv64={:016x} hex={}",
        ints.len(),
        fnv1a64(&bytes),
        hex_preview(&bytes)
    );
}

fn compute_statement_digest(pp: &BackendPP, label: u8, bytes: &[u8]) -> [u8; STATEMENT_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"ORHE_PAIR_BINDING_V1");
    hasher.update(pp.family.to_le_bytes());
    hasher.update(pp.bit_width.to_le_bytes());
    hasher.update([label]);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn compute_public_inputs(pp: &BackendPP, a_bytes: &[u8], b_bytes: &[u8]) -> Vec<F> {
    let a_digest = compute_statement_digest(pp, b'A', a_bytes);
    let b_digest = compute_statement_digest(pp, b'B', b_bytes);
    a_digest
        .into_iter()
        .chain(b_digest)
        .map(|byte| GoldilocksField::from_canonical_u64(byte as u64))
        .collect()
}

fn compute_signext_public_inputs(
    pp: &BackendPP,
    d_bytes: &[u8],
    s_bytes: &[u8],
    t_bytes: &[u8],
) -> Vec<F> {
    let d_digest = compute_statement_digest(pp, b'A', d_bytes);
    let s_digest = compute_statement_digest(pp, b'B', s_bytes);
    let t_digest = compute_statement_digest(pp, b'C', t_bytes);
    d_digest
        .into_iter()
        .chain(s_digest)
        .chain(t_digest)
        .map(|byte| GoldilocksField::from_canonical_u64(byte as u64))
        .collect()
}

fn compute_signext_semantic_public_inputs(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
) -> Vec<F> {
    compute_stmt_wit_public_inputs(pp, stmt_bytes, wit_bytes)
}

fn compute_stmt_wit_public_inputs(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
) -> Vec<F> {
    let stmt_digest = compute_statement_digest(pp, b'S', stmt_bytes);
    let wit_digest = compute_statement_digest(pp, b'W', wit_bytes);
    stmt_digest
        .into_iter()
        .chain(wit_digest)
        .map(|byte| GoldilocksField::from_canonical_u64(byte as u64))
        .collect()
}

fn field_from_i32(v: i32) -> F {
    let signed = i64::from(v);
    if signed >= 0 {
        F::from_canonical_u64(signed as u64)
    } else {
        -F::from_canonical_u64((-signed) as u64)
    }
}

fn build_family_circuit(public_input_count: usize) -> (CircuitData<F, C, D>, Vec<Target>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut public_targets = Vec::with_capacity(public_input_count);
    for _ in 0..public_input_count {
        public_targets.push(builder.add_virtual_public_input());
    }

    let data = builder.build::<C>();
    (data, public_targets)
}

fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let end = *offset + 4;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_bool_vec(bytes: &[u8], offset: &mut usize, len: usize) -> Option<Vec<bool>> {
    let slice = bytes.get(*offset..(*offset + len))?;
    *offset += len;
    if slice.iter().any(|&b| b > 1) {
        return None;
    }
    Some(slice.iter().map(|&b| b != 0).collect())
}

fn parse_signext_witness(bytes: &[u8], expected_bit_width: usize) -> Option<SignextWitness> {
    let mut offset = 0usize;
    let version = read_u32_le(bytes, &mut offset)?;
    let bit_width = read_u32_le(bytes, &mut offset)? as usize;
    if version != 1 || bit_width != expected_bit_width {
        return None;
    }

    let lhs_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let rhs_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let b_not_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let xor_ab_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_ab_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_a_cin_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_b_cin_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let carry_or_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let carry_out_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let diff_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let c_sgn_bit = *bytes.get(offset)? != 0;
    offset += 1;
    if offset != bytes.len() {
        return None;
    }

    Some(SignextWitness {
        lhs_bits,
        rhs_bits,
        b_not_bits,
        xor_ab_bits,
        and_ab_bits,
        and_a_cin_bits,
        and_b_cin_bits,
        carry_or_bits,
        carry_out_bits,
        diff_bits,
        c_sgn_bit,
    })
}

fn read_i32_le(bytes: &[u8], offset: &mut usize) -> Option<i32> {
    let end = *offset + 4;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(i32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_i32_vec(bytes: &[u8], offset: &mut usize, len: usize) -> Option<Vec<i32>> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_i32_le(bytes, offset)?);
    }
    Some(out)
}

fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let end = *offset + 8;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(u64::from_le_bytes(chunk.try_into().ok()?))
}

fn read_nested_slice<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = read_u64_le(bytes, offset)? as usize;
    let end = (*offset).checked_add(len)?;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(chunk)
}

fn expect_partial_envelope(bytes: &[u8], expected_kind: u32) -> Option<usize> {
    if bytes.get(0..4)? != b"ORPS" {
        return None;
    }
    let mut offset = 4usize;
    let version = read_u32_le(bytes, &mut offset)?;
    let kind = read_u32_le(bytes, &mut offset)?;
    if version != ORHE_SIGNEXT_PARTIAL_BACKEND_VERSION || kind != expected_kind {
        return None;
    }
    Some(offset)
}

fn parse_signext_semantic_statement(bytes: &[u8]) -> Option<SignextSemanticStatement> {
    let mut offset = expect_partial_envelope(bytes, ORHE_SIGNEXT_SEM_STMT_KIND)?;
    let relation_id = read_u32_le(bytes, &mut offset)?;
    let _ctx = bytes.get(offset..offset + 160)?;
    offset += 160;
    let _d_ser = read_nested_slice(bytes, &mut offset)?;
    let _pbs_input_ser = read_nested_slice(bytes, &mut offset)?;
    let _c_sgn_ser = read_nested_slice(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Some(SignextSemanticStatement { relation_id })
}

fn parse_signext_semantic_witness(bytes: &[u8]) -> Option<SignextSemanticWitness> {
    let mut offset = expect_partial_envelope(bytes, ORHE_SIGNEXT_SEM_WIT_KIND)?;
    let n = read_u32_le(bytes, &mut offset)? as usize;
    let boundary = read_u32_le(bytes, &mut offset)? as usize;
    let first_positive = read_u32_le(bytes, &mut offset)? != 0;
    if n != ORHE_SIGNEXT_SEM_N || boundary > n {
        return None;
    }
    let accum_zero_poly = read_i32_vec(bytes, &mut offset, n)?;
    let accum_message_poly = read_i32_vec(bytes, &mut offset, n)?;
    let blind_rot_zero_poly = read_i32_vec(bytes, &mut offset, n)?;
    let blind_rot_message_poly = read_i32_vec(bytes, &mut offset, n)?;
    let pre_ks_a = read_i32_vec(bytes, &mut offset, n)?;
    let pre_ks_b = read_i32_le(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Some(SignextSemanticWitness {
        n,
        boundary,
        first_positive,
        accum_zero_poly,
        accum_message_poly,
        blind_rot_zero_poly,
        blind_rot_message_poly,
        pre_ks_a,
        pre_ks_b,
    })
}

fn expect_pbs_semantic_envelope(bytes: &[u8], expected_kind: u32) -> Option<usize> {
    if bytes.get(0..4)? != b"OPBS" {
        return None;
    }
    let mut offset = 4usize;
    let version = read_u32_le(bytes, &mut offset)?;
    let kind = read_u32_le(bytes, &mut offset)?;
    if version != ORHE_PBS_SEMANTIC_VERSION || kind != expected_kind {
        return None;
    }
    Some(offset)
}

fn parse_pbs_semantic_statement(bytes: &[u8]) -> Option<PbsSemanticStatement> {
    let mut offset = expect_pbs_semantic_envelope(bytes, ORHE_PBS_SEMANTIC_KIND_STMT)?;
    let relation_id = read_u32_le(bytes, &mut offset)?;
    let _ctx = bytes.get(offset..offset + 160)?;
    offset += 160;
    let _x_ser = read_nested_slice(bytes, &mut offset)?;
    let _y_ser = read_nested_slice(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Some(PbsSemanticStatement { relation_id })
}

fn parse_pbs_semantic_witness(bytes: &[u8]) -> Option<PbsSemanticWitness> {
    let mut offset = expect_pbs_semantic_envelope(bytes, ORHE_PBS_SEMANTIC_KIND_WIT)?;
    let relation_id = read_u32_le(bytes, &mut offset)?;
    let nbits = read_u32_le(bytes, &mut offset)? as usize;
    let lwe_n = read_u32_le(bytes, &mut offset)? as usize;
    let flat_len = nbits.checked_mul(lwe_n)?;
    let mut x_coeffs = Vec::with_capacity(flat_len);
    let mut x_b = Vec::with_capacity(nbits);
    let mut y_coeffs = Vec::with_capacity(flat_len);
    let mut y_b = Vec::with_capacity(nbits);
    for _ in 0..nbits {
        for _ in 0..lwe_n {
            x_coeffs.push(read_u32_le(bytes, &mut offset)?);
        }
        x_b.push(read_u32_le(bytes, &mut offset)?);
        for _ in 0..lwe_n {
            y_coeffs.push(read_u32_le(bytes, &mut offset)?);
        }
        y_b.push(read_u32_le(bytes, &mut offset)?);
    }
    if offset != bytes.len() {
        return None;
    }
    Some(PbsSemanticWitness {
        relation_id,
        nbits,
        lwe_n,
        x_coeffs,
        x_b,
        y_coeffs,
        y_b,
    })
}

fn expect_sub_semantic_envelope(bytes: &[u8], expected_kind: u32) -> Option<usize> {
    if bytes.get(0..4)? != b"ORSB" {
        return None;
    }
    let mut offset = 4usize;
    let version = read_u32_le(bytes, &mut offset)?;
    let kind = read_u32_le(bytes, &mut offset)?;
    if version != ORHE_SUB_PARTIAL_VERSION || kind != expected_kind {
        return None;
    }
    Some(offset)
}

fn parse_sub_semantic_statement(bytes: &[u8]) -> Option<SubSemanticStatement> {
    let mut offset = expect_sub_semantic_envelope(bytes, ORHE_SUB_PARTIAL_KIND_STMT)?;
    let relation_id = read_u32_le(bytes, &mut offset)?;
    let _ctx = bytes.get(offset..offset + 160)?;
    offset += 160;
    let _lhs = read_nested_slice(bytes, &mut offset)?;
    let _rhs = read_nested_slice(bytes, &mut offset)?;
    let _diff = read_nested_slice(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Some(SubSemanticStatement { relation_id })
}

fn parse_sub_semantic_witness(bytes: &[u8]) -> Option<SubSemanticWitness> {
    let mut offset = expect_sub_semantic_envelope(bytes, ORHE_SUB_PARTIAL_KIND_WIT)?;
    let bit_width = read_u32_le(bytes, &mut offset)? as usize;
    let lhs_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let rhs_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let b_not_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let xor_ab_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_ab_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_a_cin_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let and_b_cin_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let carry_or_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let carry_out_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    let diff_bits = read_bool_vec(bytes, &mut offset, bit_width)?;
    if offset != bytes.len() {
        return None;
    }
    Some(SubSemanticWitness {
        bit_width,
        lhs_bits,
        rhs_bits,
        b_not_bits,
        xor_ab_bits,
        and_ab_bits,
        and_a_cin_bits,
        and_b_cin_bits,
        carry_or_bits,
        carry_out_bits,
        diff_bits,
    })
}

fn connect_bool(builder: &mut CircuitBuilder<F, D>, lhs: BoolTarget, rhs: BoolTarget) {
    builder.connect(lhs.target, rhs.target);
}

fn build_signext_circuit(bit_width: usize) -> (CircuitData<F, C, D>, Vec<Target>, SignextTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut public_targets = Vec::with_capacity(SIGNEXT_PUBLIC_INPUT_COUNT);
    for _ in 0..SIGNEXT_PUBLIC_INPUT_COUNT {
        public_targets.push(builder.add_virtual_public_input());
    }

    let mut alloc_bits = |builder: &mut CircuitBuilder<F, D>| -> Vec<BoolTarget> {
        (0..bit_width)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect()
    };

    let lhs_bits = alloc_bits(&mut builder);
    let rhs_bits = alloc_bits(&mut builder);
    let b_not_bits = alloc_bits(&mut builder);
    let xor_ab_bits = alloc_bits(&mut builder);
    let and_ab_bits = alloc_bits(&mut builder);
    let and_a_cin_bits = alloc_bits(&mut builder);
    let and_b_cin_bits = alloc_bits(&mut builder);
    let carry_or_bits = alloc_bits(&mut builder);
    let carry_out_bits = alloc_bits(&mut builder);
    let diff_bits = alloc_bits(&mut builder);
    let c_sgn_bit = builder.add_virtual_bool_target_safe();

    let one = builder._true();
    let two = GoldilocksField::from_canonical_u64(2);

    for i in 0..bit_width {
        let cin = if i == 0 { one } else { carry_out_bits[i - 1] };

        let rhs_not = builder.not(rhs_bits[i]);
        connect_bool(&mut builder, b_not_bits[i], rhs_not);

        let lhs_mul_bnot = builder.and(lhs_bits[i], b_not_bits[i]);
        connect_bool(&mut builder, and_ab_bits[i], lhs_mul_bnot);

        let lhs_mul_cin = builder.and(lhs_bits[i], cin);
        connect_bool(&mut builder, and_a_cin_bits[i], lhs_mul_cin);

        let bnot_mul_cin = builder.and(b_not_bits[i], cin);
        connect_bool(&mut builder, and_b_cin_bits[i], bnot_mul_cin);

        let xor_ab_expr = {
            let sum = builder.add(lhs_bits[i].target, b_not_bits[i].target);
            let two_mul = builder.mul_const(two, lhs_mul_bnot.target);
            builder.sub(sum, two_mul)
        };
        builder.connect(xor_ab_bits[i].target, xor_ab_expr);

        let carry_or_val = builder.or(and_ab_bits[i], and_a_cin_bits[i]);
        connect_bool(&mut builder, carry_or_bits[i], carry_or_val);
        let carry_out_val = builder.or(carry_or_bits[i], and_b_cin_bits[i]);
        connect_bool(&mut builder, carry_out_bits[i], carry_out_val);

        let xor_diff_mul = builder.mul(xor_ab_bits[i].target, cin.target);
        let diff_expr = {
            let sum = builder.add(xor_ab_bits[i].target, cin.target);
            let two_mul = builder.mul_const(two, xor_diff_mul);
            builder.sub(sum, two_mul)
        };
        builder.connect(diff_bits[i].target, diff_expr);
    }

    builder.connect(c_sgn_bit.target, diff_bits[bit_width - 1].target);

    let data = builder.build::<C>();
    let targets = SignextTargets {
        lhs_bits,
        rhs_bits,
        b_not_bits,
        xor_ab_bits,
        and_ab_bits,
        and_a_cin_bits,
        and_b_cin_bits,
        carry_or_bits,
        carry_out_bits,
        diff_bits,
        c_sgn_bit,
    };
    (data, public_targets, targets)
}

fn build_sub_semantic_circuit(
    bit_width: usize,
) -> (CircuitData<F, C, D>, Vec<Target>, SubSemanticTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut public_targets = Vec::with_capacity(SUB_SEMANTIC_PUBLIC_INPUT_COUNT);
    for _ in 0..SUB_SEMANTIC_PUBLIC_INPUT_COUNT {
        public_targets.push(builder.add_virtual_public_input());
    }

    let mut alloc_bits = |builder: &mut CircuitBuilder<F, D>| -> Vec<BoolTarget> {
        (0..bit_width)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect()
    };

    let lhs_bits = alloc_bits(&mut builder);
    let rhs_bits = alloc_bits(&mut builder);
    let b_not_bits = alloc_bits(&mut builder);
    let xor_ab_bits = alloc_bits(&mut builder);
    let and_ab_bits = alloc_bits(&mut builder);
    let and_a_cin_bits = alloc_bits(&mut builder);
    let and_b_cin_bits = alloc_bits(&mut builder);
    let carry_or_bits = alloc_bits(&mut builder);
    let carry_out_bits = alloc_bits(&mut builder);
    let diff_bits = alloc_bits(&mut builder);

    let one = builder._true();
    let two = GoldilocksField::from_canonical_u64(2);

    for i in 0..bit_width {
        let cin = if i == 0 { one } else { carry_out_bits[i - 1] };

        let rhs_not = builder.not(rhs_bits[i]);
        connect_bool(&mut builder, b_not_bits[i], rhs_not);

        let lhs_mul_bnot = builder.and(lhs_bits[i], b_not_bits[i]);
        connect_bool(&mut builder, and_ab_bits[i], lhs_mul_bnot);

        let lhs_mul_cin = builder.and(lhs_bits[i], cin);
        connect_bool(&mut builder, and_a_cin_bits[i], lhs_mul_cin);

        let bnot_mul_cin = builder.and(b_not_bits[i], cin);
        connect_bool(&mut builder, and_b_cin_bits[i], bnot_mul_cin);

        let xor_ab_expr = {
            let sum = builder.add(lhs_bits[i].target, b_not_bits[i].target);
            let two_mul = builder.mul_const(two, lhs_mul_bnot.target);
            builder.sub(sum, two_mul)
        };
        builder.connect(xor_ab_bits[i].target, xor_ab_expr);

        let carry_or_val = builder.or(and_ab_bits[i], and_a_cin_bits[i]);
        connect_bool(&mut builder, carry_or_bits[i], carry_or_val);
        let carry_out_val = builder.or(carry_or_bits[i], and_b_cin_bits[i]);
        connect_bool(&mut builder, carry_out_bits[i], carry_out_val);

        let xor_diff_mul = builder.mul(xor_ab_bits[i].target, cin.target);
        let diff_expr = {
            let sum = builder.add(xor_ab_bits[i].target, cin.target);
            let two_mul = builder.mul_const(two, xor_diff_mul);
            builder.sub(sum, two_mul)
        };
        builder.connect(diff_bits[i].target, diff_expr);
    }

    let data = builder.build::<C>();
    let targets = SubSemanticTargets {
        lhs_bits,
        rhs_bits,
        b_not_bits,
        xor_ab_bits,
        and_ab_bits,
        and_a_cin_bits,
        and_b_cin_bits,
        carry_or_bits,
        carry_out_bits,
        diff_bits,
    };
    (data, public_targets, targets)
}

fn build_pbs_semantic_circuit(
    bit_width: usize,
    lwe_n: usize,
) -> (CircuitData<F, C, D>, Vec<Target>, PbsSemanticTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut public_targets = Vec::with_capacity(PBS_SEMANTIC_PUBLIC_INPUT_COUNT);
    for _ in 0..PBS_SEMANTIC_PUBLIC_INPUT_COUNT {
        public_targets.push(builder.add_virtual_public_input());
    }

    let relation_id = builder.add_virtual_target();
    let is_t2 = builder.add_virtual_bool_target_safe();
    let is_t3 = builder.add_virtual_bool_target_safe();
    let is_t4 = builder.add_virtual_bool_target_safe();
    let is_t5 = builder.add_virtual_bool_target_safe();

    let flat_len = bit_width * lwe_n;
    let x_coeffs = (0..flat_len).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let x_b = (0..bit_width).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let y_coeffs = (0..flat_len).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let y_b = (0..bit_width).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let x_coeff_inv = (0..flat_len).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let x_coeff_nz = (0..flat_len)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<_>>();
    let x_b_inv = (0..bit_width).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
    let x_b_nz = (0..bit_width)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<_>>();

    let zero = builder.zero();
    let one = builder.one();
    let torus_modulus = builder.constant(F::from_canonical_u64(1u64 << 32));
    let false_b = builder.constant(F::from_canonical_u64(ORHE_FALSE_TORUS_B));
    let sum_t23 = builder.add(is_t2.target, is_t3.target);
    let sum_t45 = builder.add(is_t4.target, is_t5.target);
    let sum_all = builder.add(sum_t23, sum_t45);
    builder.connect(sum_all, one);
    let relation_expr = {
        let two = builder.constant(F::from_canonical_u64(2));
        let three = builder.constant(F::from_canonical_u64(3));
        let four = builder.constant(F::from_canonical_u64(4));
        let five = builder.constant(F::from_canonical_u64(5));
        let t2 = builder.mul(two, is_t2.target);
        let t3 = builder.mul(three, is_t3.target);
        let t4 = builder.mul(four, is_t4.target);
        let t5 = builder.mul(five, is_t5.target);
        let lhs = builder.add(t2, t3);
        let rhs = builder.add(t4, t5);
        builder.add(lhs, rhs)
    };
    builder.connect(relation_id, relation_expr);

    for i in 0..flat_len {
        let nz = x_coeff_nz[i].target;
        let inv_check = builder.mul(x_coeffs[i], x_coeff_inv[i]);
        builder.connect(inv_check, nz);
        let one_minus_nz = builder.sub(one, nz);
        let zero_check = builder.mul(x_coeffs[i], one_minus_nz);
        builder.connect(zero_check, zero);
        let wrap_term = builder.mul(torus_modulus, nz);
        let neg_expr = builder.sub(wrap_term, x_coeffs[i]);

        let bit = i / lwe_n;
        let src_msb_idx = (bit_width - 1) * lwe_n + (i % lwe_n);
        let t2_expr = if bit < 4 { x_coeffs[i] } else { zero };
        let t4_expr = if bit < 2 { x_coeffs[i] } else { zero };
        let t5_expr = if bit == 0 { x_coeffs[src_msb_idx] } else { zero };

        let e_t2 = builder.mul(is_t2.target, t2_expr);
        let e_t3 = builder.mul(is_t3.target, neg_expr);
        let e_t4 = builder.mul(is_t4.target, t4_expr);
        let e_t5 = builder.mul(is_t5.target, t5_expr);
        let lhs = builder.add(e_t2, e_t3);
        let rhs = builder.add(e_t4, e_t5);
        let expected = builder.add(lhs, rhs);
        builder.connect(y_coeffs[i], expected);
    }
    for i in 0..bit_width {
        let nz = x_b_nz[i].target;
        let inv_check = builder.mul(x_b[i], x_b_inv[i]);
        builder.connect(inv_check, nz);
        let one_minus_nz = builder.sub(one, nz);
        let zero_check = builder.mul(x_b[i], one_minus_nz);
        builder.connect(zero_check, zero);
        let wrap_term = builder.mul(torus_modulus, nz);
        let neg_expr = builder.sub(wrap_term, x_b[i]);
        let t2_expr = if i < 4 { x_b[i] } else { false_b };
        let t4_expr = if i < 2 { x_b[i] } else { false_b };
        let t5_expr = if i == 0 { x_b[bit_width - 1] } else { false_b };
        let e_t2 = builder.mul(is_t2.target, t2_expr);
        let e_t3 = builder.mul(is_t3.target, neg_expr);
        let e_t4 = builder.mul(is_t4.target, t4_expr);
        let e_t5 = builder.mul(is_t5.target, t5_expr);
        let lhs = builder.add(e_t2, e_t3);
        let rhs = builder.add(e_t4, e_t5);
        let expected = builder.add(lhs, rhs);
        builder.connect(y_b[i], expected);
    }

    let data = builder.build::<C>();
    let targets = PbsSemanticTargets {
        relation_id,
        is_t2,
        is_t3,
        is_t4,
        is_t5,
        x_coeffs,
        x_b,
        y_coeffs,
        y_b,
        x_coeff_inv,
        x_coeff_nz,
        x_b_inv,
        x_b_nz,
    };
    (data, public_targets, targets)
}

fn build_signext_semantic_circuit() -> (CircuitData<F, C, D>, Vec<Target>, SignextSemanticTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut public_targets = Vec::with_capacity(SIGNEXT_SEMANTIC_PUBLIC_INPUT_COUNT);
    for _ in 0..SIGNEXT_SEMANTIC_PUBLIC_INPUT_COUNT {
        public_targets.push(builder.add_virtual_public_input());
    }

    let boundary = builder.add_virtual_target();
    let first_positive = builder.add_virtual_bool_target_safe();
    let prefix_bits: Vec<BoolTarget> = (0..ORHE_SIGNEXT_SEM_N)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();
    let alloc_targets = |builder: &mut CircuitBuilder<F, D>| -> Vec<Target> {
        (0..ORHE_SIGNEXT_SEM_N)
            .map(|_| builder.add_virtual_target())
            .collect()
    };
    let accum_zero_poly = alloc_targets(&mut builder);
    let accum_message_poly = alloc_targets(&mut builder);
    let blind_rot_zero_poly = alloc_targets(&mut builder);
    let blind_rot_message_poly = alloc_targets(&mut builder);
    let pre_ks_a = alloc_targets(&mut builder);
    let pre_ks_b = builder.add_virtual_target();

    let zero = builder.zero();
    let one = builder.one();
    let mu = builder.constant(field_from_i32(ORHE_SIGNEXT_MU));
    let neg_mu = builder.constant(field_from_i32(-ORHE_SIGNEXT_MU));
    let two_mu = builder.constant(field_from_i32(2 * ORHE_SIGNEXT_MU));
    let fp = first_positive.target;

    let mut prefix_sum = zero;
    for bit in prefix_bits.iter() {
        prefix_sum = builder.add(prefix_sum, bit.target);
    }
    builder.connect(prefix_sum, boundary);

    for i in 0..ORHE_SIGNEXT_SEM_N {
        builder.connect(accum_zero_poly[i], zero);
        if i + 1 < ORHE_SIGNEXT_SEM_N {
            let not_prev = builder.sub(one, prefix_bits[i].target);
            let bad_transition = builder.mul(prefix_bits[i + 1].target, not_prev);
            builder.connect(bad_transition, zero);
        }

        let pos_case = {
            let add = builder.mul(prefix_bits[i].target, two_mu);
            builder.add(neg_mu, add)
        };
        let neg_case = {
            let sub = builder.mul(prefix_bits[i].target, two_mu);
            builder.sub(mu, sub)
        };
        let fp_pos = builder.mul(fp, pos_case);
        let one_minus_fp = builder.sub(one, fp);
        let fp_neg = builder.mul(one_minus_fp, neg_case);
        let expected = builder.add(fp_pos, fp_neg);
        builder.connect(accum_message_poly[i], expected);
    }

    builder.connect(pre_ks_b, blind_rot_message_poly[0]);
    builder.connect(pre_ks_a[0], blind_rot_zero_poly[0]);
    for j in 1..ORHE_SIGNEXT_SEM_N {
        let expected = builder.sub(zero, blind_rot_zero_poly[ORHE_SIGNEXT_SEM_N - j]);
        builder.connect(pre_ks_a[j], expected);
    }

    let data = builder.build::<C>();
    let targets = SignextSemanticTargets {
        boundary,
        first_positive,
        prefix_bits,
        accum_zero_poly,
        accum_message_poly,
        blind_rot_zero_poly,
        blind_rot_message_poly,
        pre_ks_a,
        pre_ks_b,
    };
    (data, public_targets, targets)
}

#[no_mangle]
pub extern "C" fn orhe_rust_setup_pp(family: c_int, bit_width: c_int) -> *mut c_void {
    let (data, public_targets, signext_targets) = if family == ORHE_PROOF_FAMILY_SIGNEXT {
        let (data, public_targets, signext_targets) = build_signext_circuit(bit_width as usize);
        (data, public_targets, Some(signext_targets))
    } else {
        let (data, public_targets) = build_family_circuit(PAIR_PUBLIC_INPUT_COUNT);
        (data, public_targets, None)
    };
    let pp = BackendPP {
        family,
        bit_width,
        lwe_n: 0,
        data,
        public_targets,
        signext_targets,
        signext_semantic_targets: None,
        pbs_semantic_targets: None,
        sub_semantic_targets: None,
    };
    Box::into_raw(Box::new(pp)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn orhe_rust_setup_pbs_semantic_pp(bit_width: c_int, lwe_n: c_int) -> *mut c_void {
    let (data, public_targets, pbs_semantic_targets) =
        build_pbs_semantic_circuit(bit_width as usize, lwe_n as usize);
    let pp = BackendPP {
        family: ORHE_PROOF_FAMILY_PBS,
        bit_width,
        lwe_n,
        data,
        public_targets,
        signext_targets: None,
        signext_semantic_targets: None,
        pbs_semantic_targets: Some(pbs_semantic_targets),
        sub_semantic_targets: None,
    };
    Box::into_raw(Box::new(pp)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn orhe_rust_setup_signext_semantic_pp(bit_width: c_int) -> *mut c_void {
    let (data, public_targets, signext_semantic_targets) = build_signext_semantic_circuit();
    let pp = BackendPP {
        family: ORHE_PROOF_FAMILY_SIGNEXT,
        bit_width,
        lwe_n: 0,
        data,
        public_targets,
        signext_targets: None,
        signext_semantic_targets: Some(signext_semantic_targets),
        pbs_semantic_targets: None,
        sub_semantic_targets: None,
    };
    Box::into_raw(Box::new(pp)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn orhe_rust_setup_sub_semantic_pp(bit_width: c_int) -> *mut c_void {
    let (data, public_targets, sub_semantic_targets) =
        build_sub_semantic_circuit(bit_width as usize);
    let pp = BackendPP {
        family: ORHE_PROOF_FAMILY_SUB,
        bit_width,
        lwe_n: 0,
        data,
        public_targets,
        signext_targets: None,
        signext_semantic_targets: None,
        pbs_semantic_targets: None,
        sub_semantic_targets: Some(sub_semantic_targets),
    };
    Box::into_raw(Box::new(pp)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn orhe_rust_free_pp(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle as *mut BackendPP));
    }
}

fn alloc_bytes(out_ptr: *mut *mut c_uchar, out_len: *mut c_ulonglong, bytes: Vec<u8>) -> c_int {
    let len = bytes.len() as u64;
    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8;

    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }

    1
}

fn prove_pair(
    pp: &BackendPP,
    a_bytes: &[u8],
    b_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let public_inputs = compute_public_inputs(pp, a_bytes, b_bytes);

    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    alloc_bytes(out_ptr, out_len, bytes)
}

fn verify_pair(pp: &BackendPP, a_bytes: &[u8], b_bytes: &[u8], proof_bytes: &[u8]) -> c_int {
    let expected_public_inputs = compute_public_inputs(pp, a_bytes, b_bytes);

    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };

    if proof.public_inputs.len() != PAIR_PUBLIC_INPUT_COUNT {
        return 0;
    }

    if proof.public_inputs != expected_public_inputs {
        return 0;
    }

    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn prove_triplet(
    pp: &BackendPP,
    a_bytes: &[u8],
    b_bytes: &[u8],
    c_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let public_inputs = compute_signext_public_inputs(pp, a_bytes, b_bytes, c_bytes);

    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    alloc_bytes(out_ptr, out_len, bytes)
}

fn verify_triplet(
    pp: &BackendPP,
    a_bytes: &[u8],
    b_bytes: &[u8],
    c_bytes: &[u8],
    proof_bytes: &[u8],
) -> c_int {
    let expected_public_inputs = compute_signext_public_inputs(pp, a_bytes, b_bytes, c_bytes);

    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };

    if proof.public_inputs.len() != SIGNEXT_PUBLIC_INPUT_COUNT {
        return 0;
    }

    if proof.public_inputs != expected_public_inputs {
        return 0;
    }

    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn set_bool_vec(
    pw: &mut PartialWitness<F>,
    targets: &[BoolTarget],
    values: &[bool],
) -> bool {
    if targets.len() != values.len() {
        return false;
    }
    for (target, value) in targets.iter().zip(values.iter().copied()) {
        if pw.set_bool_target(*target, value).is_err() {
            return false;
        }
    }
    true
}

fn prove_signext_with_witness(
    pp: &BackendPP,
    d_bytes: &[u8],
    s_bytes: &[u8],
    t_bytes: &[u8],
    witness_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let targets = match &pp.signext_targets {
        Some(t) => t,
        None => return 0,
    };
    let witness = match parse_signext_witness(witness_bytes, pp.bit_width as usize) {
        Some(w) => w,
        None => return 0,
    };
    let public_inputs = compute_signext_public_inputs(pp, d_bytes, s_bytes, t_bytes);

    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }

    if !set_bool_vec(&mut pw, &targets.lhs_bits, &witness.lhs_bits)
        || !set_bool_vec(&mut pw, &targets.rhs_bits, &witness.rhs_bits)
        || !set_bool_vec(&mut pw, &targets.b_not_bits, &witness.b_not_bits)
        || !set_bool_vec(&mut pw, &targets.xor_ab_bits, &witness.xor_ab_bits)
        || !set_bool_vec(&mut pw, &targets.and_ab_bits, &witness.and_ab_bits)
        || !set_bool_vec(&mut pw, &targets.and_a_cin_bits, &witness.and_a_cin_bits)
        || !set_bool_vec(&mut pw, &targets.and_b_cin_bits, &witness.and_b_cin_bits)
        || !set_bool_vec(&mut pw, &targets.carry_or_bits, &witness.carry_or_bits)
        || !set_bool_vec(&mut pw, &targets.carry_out_bits, &witness.carry_out_bits)
        || !set_bool_vec(&mut pw, &targets.diff_bits, &witness.diff_bits)
        || pw.set_bool_target(targets.c_sgn_bit, witness.c_sgn_bit).is_err()
    {
        return 0;
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    alloc_bytes(out_ptr, out_len, bytes)
}

fn set_target_vec_from_i32(
    pw: &mut PartialWitness<F>,
    targets: &[Target],
    values: &[i32],
) -> bool {
    if targets.len() != values.len() {
        return false;
    }
    for (target, value) in targets.iter().zip(values.iter().copied()) {
        if pw.set_target(*target, field_from_i32(value)).is_err() {
            return false;
        }
    }
    true
}

fn set_target_vec_from_u32(
    pw: &mut PartialWitness<F>,
    targets: &[Target],
    values: &[u32],
) -> bool {
    if targets.len() != values.len() {
        return false;
    }
    for (target, value) in targets.iter().zip(values.iter().copied()) {
        if pw
            .set_target(*target, F::from_canonical_u64(value as u64))
            .is_err()
        {
            return false;
        }
    }
    true
}

fn build_prefix_witness(boundary: usize, n: usize) -> Vec<bool> {
    (0..n).map(|i| i < boundary).collect()
}

fn prove_pbs_semantic(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let stmt = match parse_pbs_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let wit = match parse_pbs_semantic_witness(wit_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let targets = match &pp.pbs_semantic_targets {
        Some(t) => t,
        None => return 0,
    };
    let supported_relation = matches!(
        stmt.relation_id,
        ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE
            | ORHE_PBS_RELATION_T3_BITWISE_NOT
            | ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS
            | ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB
    );
    if !supported_relation
        || wit.relation_id != stmt.relation_id
        || wit.nbits != pp.bit_width as usize
        || wit.lwe_n != pp.lwe_n as usize
    {
        return 0;
    }

    let public_inputs = compute_stmt_wit_public_inputs(pp, stmt_bytes, wit_bytes);
    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }
    let is_t2 = stmt.relation_id == ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE;
    let is_t3 = stmt.relation_id == ORHE_PBS_RELATION_T3_BITWISE_NOT;
    let is_t4 = stmt.relation_id == ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS;
    let is_t5 = stmt.relation_id == ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB;
    if pw
        .set_target(targets.relation_id, F::from_canonical_u64(stmt.relation_id as u64))
        .is_err()
        || pw.set_bool_target(targets.is_t2, is_t2).is_err()
        || pw.set_bool_target(targets.is_t3, is_t3).is_err()
        || pw.set_bool_target(targets.is_t4, is_t4).is_err()
        || pw.set_bool_target(targets.is_t5, is_t5).is_err()
    {
        return 0;
    }
    if !set_target_vec_from_u32(&mut pw, &targets.x_coeffs, &wit.x_coeffs)
        || !set_target_vec_from_u32(&mut pw, &targets.x_b, &wit.x_b)
        || !set_target_vec_from_u32(&mut pw, &targets.y_coeffs, &wit.y_coeffs)
        || !set_target_vec_from_u32(&mut pw, &targets.y_b, &wit.y_b)
    {
        return 0;
    }
    for ((inv_target, nz_target), value) in targets
        .x_coeff_inv
        .iter()
        .zip(targets.x_coeff_nz.iter())
        .zip(wit.x_coeffs.iter().copied())
    {
        let nz = value != 0;
        let inv = if nz {
            F::from_canonical_u64(value as u64).inverse()
        } else {
            F::ZERO
        };
        if pw.set_target(*inv_target, inv).is_err()
            || pw.set_bool_target(*nz_target, nz).is_err()
        {
            return 0;
        }
    }
    for ((inv_target, nz_target), value) in targets
        .x_b_inv
        .iter()
        .zip(targets.x_b_nz.iter())
        .zip(wit.x_b.iter().copied())
    {
        let nz = value != 0;
        let inv = if nz {
            F::from_canonical_u64(value as u64).inverse()
        } else {
            F::ZERO
        };
        if pw.set_target(*inv_target, inv).is_err()
            || pw.set_bool_target(*nz_target, nz).is_err()
        {
            return 0;
        }
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    alloc_bytes(out_ptr, out_len, bytes)
}

fn verify_pbs_semantic(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    proof_bytes: &[u8],
) -> c_int {
    let stmt = match parse_pbs_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let wit = match parse_pbs_semantic_witness(wit_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let supported_relation = matches!(
        stmt.relation_id,
        ORHE_PBS_RELATION_T2_MASK_LOW_NIBBLE
            | ORHE_PBS_RELATION_T3_BITWISE_NOT
            | ORHE_PBS_RELATION_T4_MASK_LOW_TWO_BITS
            | ORHE_PBS_RELATION_T5_EXTRACT_MSB_TO_LSB
    );
    if !supported_relation
        || wit.relation_id != stmt.relation_id
        || wit.nbits != pp.bit_width as usize
        || wit.lwe_n != pp.lwe_n as usize
    {
        return 0;
    }

    let expected_public_inputs = compute_stmt_wit_public_inputs(pp, stmt_bytes, wit_bytes);
    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };
    if proof.public_inputs.len() != PBS_SEMANTIC_PUBLIC_INPUT_COUNT {
        return 0;
    }
    if proof.public_inputs != expected_public_inputs {
        return 0;
    }
    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn prove_signext_semantic_partial(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let _stmt = match parse_signext_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let wit = match parse_signext_semantic_witness(wit_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let targets = match &pp.signext_semantic_targets {
        Some(t) => t,
        None => return 0,
    };

    let public_inputs = compute_signext_semantic_public_inputs(pp, stmt_bytes, wit_bytes);
    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }
    if pw
        .set_target(targets.boundary, F::from_canonical_u64(wit.boundary as u64))
        .is_err()
        || pw
            .set_bool_target(targets.first_positive, wit.first_positive)
            .is_err()
    {
        return 0;
    }
    let prefix = build_prefix_witness(wit.boundary, wit.n);
    if !set_bool_vec(&mut pw, &targets.prefix_bits, &prefix)
        || !set_target_vec_from_i32(&mut pw, &targets.accum_zero_poly, &wit.accum_zero_poly)
        || !set_target_vec_from_i32(&mut pw, &targets.accum_message_poly, &wit.accum_message_poly)
        || !set_target_vec_from_i32(&mut pw, &targets.blind_rot_zero_poly, &wit.blind_rot_zero_poly)
        || !set_target_vec_from_i32(&mut pw, &targets.blind_rot_message_poly, &wit.blind_rot_message_poly)
        || !set_target_vec_from_i32(&mut pw, &targets.pre_ks_a, &wit.pre_ks_a)
        || pw
            .set_target(targets.pre_ks_b, field_from_i32(wit.pre_ks_b))
            .is_err()
    {
        return 0;
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    alloc_bytes(out_ptr, out_len, bytes)
}

fn verify_signext_semantic_partial(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    proof_bytes: &[u8],
) -> c_int {
    let stmt = match parse_signext_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    if stmt.relation_id != ORHE_SIGNEXT_RELATION_PARTIAL_B1_B3 {
        return 0;
    }
    if parse_signext_semantic_witness(wit_bytes).is_none() {
        return 0;
    }

    let expected_public_inputs = compute_signext_semantic_public_inputs(pp, stmt_bytes, wit_bytes);
    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };
    if proof.public_inputs.len() != SIGNEXT_SEMANTIC_PUBLIC_INPUT_COUNT {
        return 0;
    }
    if proof.public_inputs != expected_public_inputs {
        return 0;
    }
    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn prove_sub_semantic(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    let stmt = match parse_sub_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let wit = match parse_sub_semantic_witness(wit_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let targets = match &pp.sub_semantic_targets {
        Some(t) => t,
        None => return 0,
    };
    if stmt.relation_id != ORHE_SUB_RELATION_PARTIAL_RIPPLE || wit.bit_width != pp.bit_width as usize {
        return 0;
    }

    let public_inputs = compute_stmt_wit_public_inputs(pp, stmt_bytes, wit_bytes);
    let mut pw = PartialWitness::new();
    for (target, value) in pp.public_targets.iter().zip(public_inputs.iter().copied()) {
        if pw.set_target(*target, value).is_err() {
            return 0;
        }
    }

    if !set_bool_vec(&mut pw, &targets.lhs_bits, &wit.lhs_bits)
        || !set_bool_vec(&mut pw, &targets.rhs_bits, &wit.rhs_bits)
        || !set_bool_vec(&mut pw, &targets.b_not_bits, &wit.b_not_bits)
        || !set_bool_vec(&mut pw, &targets.xor_ab_bits, &wit.xor_ab_bits)
        || !set_bool_vec(&mut pw, &targets.and_ab_bits, &wit.and_ab_bits)
        || !set_bool_vec(&mut pw, &targets.and_a_cin_bits, &wit.and_a_cin_bits)
        || !set_bool_vec(&mut pw, &targets.and_b_cin_bits, &wit.and_b_cin_bits)
        || !set_bool_vec(&mut pw, &targets.carry_or_bits, &wit.carry_or_bits)
        || !set_bool_vec(&mut pw, &targets.carry_out_bits, &wit.carry_out_bits)
        || !set_bool_vec(&mut pw, &targets.diff_bits, &wit.diff_bits)
    {
        return 0;
    }

    let proof = match pp.data.prove(pw) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let bytes = match bincode::serialize(&proof) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    alloc_bytes(out_ptr, out_len, bytes)
}

fn verify_sub_semantic(
    pp: &BackendPP,
    stmt_bytes: &[u8],
    wit_bytes: &[u8],
    proof_bytes: &[u8],
) -> c_int {
    let stmt = match parse_sub_semantic_statement(stmt_bytes) {
        Some(v) => v,
        None => return 0,
    };
    let wit = match parse_sub_semantic_witness(wit_bytes) {
        Some(v) => v,
        None => return 0,
    };
    if stmt.relation_id != ORHE_SUB_RELATION_PARTIAL_RIPPLE || wit.bit_width != pp.bit_width as usize {
        return 0;
    }

    let expected_public_inputs = compute_stmt_wit_public_inputs(pp, stmt_bytes, wit_bytes);
    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };
    if proof.public_inputs.len() != SUB_SEMANTIC_PUBLIC_INPUT_COUNT {
        return 0;
    }
    if proof.public_inputs != expected_public_inputs {
        return 0;
    }
    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_pbs_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    prove_pbs_semantic(pp, stmt, wit, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_pbs_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_pbs_semantic(pp, stmt, wit, proof)
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_pbs(
    handle: *mut c_void,
    x_ptr: *const c_uchar,
    x_len: c_ulonglong,
    y_ptr: *const c_uchar,
    y_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let x = unsafe { as_slice(x_ptr, x_len) };
    let y = unsafe { as_slice(y_ptr, y_len) };
    prove_pair(pp, x, y, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_pbs(
    handle: *mut c_void,
    x_ptr: *const c_uchar,
    x_len: c_ulonglong,
    y_ptr: *const c_uchar,
    y_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let x = unsafe { as_slice(x_ptr, x_len) };
    let y = unsafe { as_slice(y_ptr, y_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_pair(pp, x, y, proof)
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_signext(
    handle: *mut c_void,
    d_ptr: *const c_uchar,
    d_len: c_ulonglong,
    s_ptr: *const c_uchar,
    s_len: c_ulonglong,
    t_ptr: *const c_uchar,
    t_len: c_ulonglong,
    w_ptr: *const c_uchar,
    w_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let d = unsafe { as_slice(d_ptr, d_len) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    let t = unsafe { as_slice(t_ptr, t_len) };
    let w = unsafe { as_slice(w_ptr, w_len) };

    if should_debug_once(&SIGNEXT_PROVE_DEBUG_COUNT) {
        debug_dump_bytes("prove_signext diff bytes", d);
        debug_dump_bytes("prove_signext claimed checkpoint bytes", s);
        debug_dump_bytes("prove_signext subtraction trace bytes", t);
        debug_dump_bytes("prove_signext boolean witness bytes", w);
        debug_dump_public_inputs(
            "prove_signext public inputs",
            &compute_signext_public_inputs(pp, d, s, t),
        );
    }

    prove_signext_with_witness(pp, d, s, t, w, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_signext(
    handle: *mut c_void,
    d_ptr: *const c_uchar,
    d_len: c_ulonglong,
    s_ptr: *const c_uchar,
    s_len: c_ulonglong,
    t_ptr: *const c_uchar,
    t_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let d = unsafe { as_slice(d_ptr, d_len) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    let t = unsafe { as_slice(t_ptr, t_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };

    let expected_public_inputs = compute_signext_public_inputs(pp, d, s, t);
    let verify_result = verify_triplet(pp, d, s, t, proof);

    if should_debug_once(&SIGNEXT_VERIFY_DEBUG_COUNT) {
        debug_dump_bytes("verify_signext diff bytes", d);
        debug_dump_bytes("verify_signext claimed checkpoint bytes", s);
        debug_dump_bytes("verify_signext subtraction trace bytes", t);
        debug_dump_bytes("verify_signext proof bytes", proof);
        debug_dump_public_inputs(
            "verify_signext expected public inputs",
            &expected_public_inputs,
        );
        eprintln!("[rust][compare-debug] verify_signext proof verification result={verify_result}");
    }

    verify_result
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_signext_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    prove_signext_semantic_partial(pp, stmt, wit, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_signext_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_signext_semantic_partial(pp, stmt, wit, proof)
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_sub_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    prove_sub_semantic(pp, stmt, wit, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_sub_semantic(
    handle: *mut c_void,
    stmt_ptr: *const c_uchar,
    stmt_len: c_ulonglong,
    wit_ptr: *const c_uchar,
    wit_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let stmt = unsafe { as_slice(stmt_ptr, stmt_len) };
    let wit = unsafe { as_slice(wit_ptr, wit_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_sub_semantic(pp, stmt, wit, proof)
}

#[no_mangle]
pub extern "C" fn orhe_rust_prove_ks(
    handle: *mut c_void,
    s_ptr: *const c_uchar,
    s_len: c_ulonglong,
    u_ptr: *const c_uchar,
    u_len: c_ulonglong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    let u = unsafe { as_slice(u_ptr, u_len) };
    prove_pair(pp, s, u, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_ks(
    handle: *mut c_void,
    s_ptr: *const c_uchar,
    s_len: c_ulonglong,
    u_ptr: *const c_uchar,
    u_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    let u = unsafe { as_slice(u_ptr, u_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_pair(pp, s, u, proof)
}

#[no_mangle]
pub extern "C" fn orhe_rust_free_buffer(ptr: *mut c_uchar, len: c_ulonglong) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}
