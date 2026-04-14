use libc::{c_int, c_uchar, c_ulonglong, c_void};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[repr(C)]
struct BackendPP {
    family: i32,
    bit_width: i32,
    data: CircuitData<F, C, D>,
    a_target: Target,
    b_target: Target,
}

unsafe fn as_slice<'a>(ptr: *const u8, len: u64) -> &'a [u8] {
    std::slice::from_raw_parts(ptr, len as usize)
}

fn encode_first_byte_as_field(bytes: &[u8]) -> F {
    let v = if bytes.is_empty() { 0u64 } else { bytes[0] as u64 };
    GoldilocksField::from_canonical_u64(v)
}

fn build_family_circuit(family: i32) -> (CircuitData<F, C, D>, Target, Target) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();

    match family {
        // PBS placeholder: prove b == a
        1 => {
            builder.connect(a, b);
        }

        // SignExt placeholder: prove b == a
        2 => {
            builder.connect(a, b);
        }

        // KS placeholder: prove b == a
        3 => {
            builder.connect(a, b);
        }

        _ => {
            builder.connect(a, b);
        }
    }

    builder.register_public_input(a);
    builder.register_public_input(b);

    let data = builder.build::<C>();
    (data, a, b)
}

#[no_mangle]
pub extern "C" fn orhe_rust_setup_pp(family: c_int, bit_width: c_int) -> *mut c_void {
    let (data, a_target, b_target) = build_family_circuit(family);
    let pp = BackendPP {
        family,
        bit_width,
        data,
        a_target,
        b_target,
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
    let a_val = encode_first_byte_as_field(a_bytes);
    let b_val = encode_first_byte_as_field(b_bytes);

    let mut pw = PartialWitness::new();
    if pw.set_target(pp.a_target, a_val).is_err() {
        return 0;
    }
    if pw.set_target(pp.b_target, b_val).is_err() {
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

fn verify_pair(
    pp: &BackendPP,
    a_bytes: &[u8],
    b_bytes: &[u8],
    proof_bytes: &[u8],
) -> c_int {
    let a_val = encode_first_byte_as_field(a_bytes);
    let b_val = encode_first_byte_as_field(b_bytes);

    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> =
        match bincode::deserialize(proof_bytes) {
            Ok(p) => p,
            Err(_) => return 0,
        };

    if proof.public_inputs.len() != 2 {
        return 0;
    }

    if proof.public_inputs[0] != a_val || proof.public_inputs[1] != b_val {
        return 0;
    }

    match pp.data.verify(proof) {
        Ok(_) => 1,
        Err(_) => 0,
    }
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
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let d = unsafe { as_slice(d_ptr, d_len) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    prove_pair(pp, d, s, out_ptr, out_len)
}

#[no_mangle]
pub extern "C" fn orhe_rust_verify_signext(
    handle: *mut c_void,
    d_ptr: *const c_uchar,
    d_len: c_ulonglong,
    s_ptr: *const c_uchar,
    s_len: c_ulonglong,
    proof_ptr: *const c_uchar,
    proof_len: c_ulonglong,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    let pp = unsafe { &*(handle as *mut BackendPP) };
    let d = unsafe { as_slice(d_ptr, d_len) };
    let s = unsafe { as_slice(s_ptr, s_len) };
    let proof = unsafe { as_slice(proof_ptr, proof_len) };
    verify_pair(pp, d, s, proof)
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
