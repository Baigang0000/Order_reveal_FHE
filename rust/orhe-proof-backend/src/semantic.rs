const VERSION: u16 = 2;
const KIND_CTX: u16 = 3;
const KIND_STMT: u16 = 4;
const KIND_B1: u16 = 5;
const KIND_B2: u16 = 6;
const KIND_B3: u16 = 7;
const KIND_B4: u16 = 8;
const KIND_WIT: u16 = 9;

struct Cursor<'a> {
    bytes: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, off: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        let out = &self.bytes[self.off..end];
        self.off = end;
        Some(out)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes = self.take(8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn nested(&mut self) -> Option<&'a [u8]> {
        let len = self.u64()? as usize;
        self.take(len)
    }

    fn done(&self) -> bool {
        self.off == self.bytes.len()
    }
}

fn expect_envelope(cur: &mut Cursor<'_>, kind: u16) -> bool {
    matches!(
        (cur.take(4), cur.u16(), cur.u16()),
        (Some(b"ORHE"), Some(k), Some(VERSION)) if k == kind
    )
}

struct CtxView<'a> {
    pbs_ks_id: &'a [u8],
    ctx_root: &'a [u8],
}

struct StatementView<'a> {
    c_sgn_ser: &'a [u8],
    ctx: CtxView<'a>,
}

struct B1View<'a> {
    pbs_input_ser: &'a [u8],
    accum_init_tlwe_ser: &'a [u8],
    ctx_root: &'a [u8],
}

struct B2View<'a> {
    pbs_input_ser: &'a [u8],
    accum_init_tlwe_ser: &'a [u8],
    blind_rot_accum_tlwe_ser: &'a [u8],
    ctx_root: &'a [u8],
}

struct B3View<'a> {
    blind_rot_accum_tlwe_ser: &'a [u8],
    pre_ks_lwe_ser: &'a [u8],
    ctx_root: &'a [u8],
}

struct B4View<'a> {
    pre_ks_lwe_ser: &'a [u8],
    c_sgn_ser: &'a [u8],
    pbs_ks_id: &'a [u8],
    ctx_root: &'a [u8],
}

struct WitnessView<'a> {
    pbs_input_ser: &'a [u8],
    pre_ks_lwe_ser: &'a [u8],
    b1: B1View<'a>,
    b2: B2View<'a>,
    b3: B3View<'a>,
    b4: B4View<'a>,
}

fn parse_ctx(bytes: &[u8]) -> Option<CtxView<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_CTX) {
        return None;
    }
    let _params_id = cur.take(32)?;
    let _lut_id = cur.take(32)?;
    let _bk_fft_id = cur.take(32)?;
    let pbs_ks_id = cur.take(32)?;
    let ctx_root = cur.take(32)?;
    if !cur.done() {
        return None;
    }
    Some(CtxView { pbs_ks_id, ctx_root })
}

fn parse_statement(bytes: &[u8]) -> Option<StatementView<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_STMT) {
        return None;
    }
    let _d_ser = cur.nested()?;
    let c_sgn_ser = cur.nested()?;
    let ctx = parse_ctx(cur.nested()?)?;
    if !cur.done() {
        return None;
    }
    Some(StatementView { c_sgn_ser, ctx })
}

fn parse_b1(bytes: &[u8]) -> Option<B1View<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_B1) {
        return None;
    }
    let pbs_input_ser = cur.nested()?;
    let accum_init_tlwe_ser = cur.nested()?;
    let ctx_root = cur.take(32)?;
    if !cur.done() {
        return None;
    }
    Some(B1View {
        pbs_input_ser,
        accum_init_tlwe_ser,
        ctx_root,
    })
}

fn parse_b2(bytes: &[u8]) -> Option<B2View<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_B2) {
        return None;
    }
    let pbs_input_ser = cur.nested()?;
    let accum_init_tlwe_ser = cur.nested()?;
    let blind_rot_accum_tlwe_ser = cur.nested()?;
    let ctx_root = cur.take(32)?;
    if !cur.done() {
        return None;
    }
    Some(B2View {
        pbs_input_ser,
        accum_init_tlwe_ser,
        blind_rot_accum_tlwe_ser,
        ctx_root,
    })
}

fn parse_b3(bytes: &[u8]) -> Option<B3View<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_B3) {
        return None;
    }
    let blind_rot_accum_tlwe_ser = cur.nested()?;
    let pre_ks_lwe_ser = cur.nested()?;
    let ctx_root = cur.take(32)?;
    if !cur.done() {
        return None;
    }
    Some(B3View {
        blind_rot_accum_tlwe_ser,
        pre_ks_lwe_ser,
        ctx_root,
    })
}

fn parse_b4(bytes: &[u8]) -> Option<B4View<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_B4) {
        return None;
    }
    let pre_ks_lwe_ser = cur.nested()?;
    let c_sgn_ser = cur.nested()?;
    let pbs_ks_id = cur.take(32)?;
    let ctx_root = cur.take(32)?;
    if !cur.done() {
        return None;
    }
    Some(B4View {
        pre_ks_lwe_ser,
        c_sgn_ser,
        pbs_ks_id,
        ctx_root,
    })
}

fn parse_witness(bytes: &[u8]) -> Option<WitnessView<'_>> {
    let mut cur = Cursor::new(bytes);
    if !expect_envelope(&mut cur, KIND_WIT) {
        return None;
    }
    let pbs_input_ser = cur.nested()?;
    let pre_ks_lwe_ser = cur.nested()?;
    let b1 = parse_b1(cur.nested()?)?;
    let b2 = parse_b2(cur.nested()?)?;
    let b3 = parse_b3(cur.nested()?)?;
    let b4 = parse_b4(cur.nested()?)?;
    if !cur.done() {
        return None;
    }
    Some(WitnessView {
        pbs_input_ser,
        pre_ks_lwe_ser,
        b1,
        b2,
        b3,
        b4,
    })
}

pub fn validate_statement_and_witness(stmt_bytes: &[u8], wit_bytes: &[u8]) -> bool {
    let stmt = match parse_statement(stmt_bytes) {
        Some(v) => v,
        None => return false,
    };
    let wit = match parse_witness(wit_bytes) {
        Some(v) => v,
        None => return false,
    };

    wit.pbs_input_ser == wit.b1.pbs_input_ser
        && wit.pbs_input_ser == wit.b2.pbs_input_ser
        && wit.b1.accum_init_tlwe_ser == wit.b2.accum_init_tlwe_ser
        && wit.b2.blind_rot_accum_tlwe_ser == wit.b3.blind_rot_accum_tlwe_ser
        && wit.pre_ks_lwe_ser == wit.b3.pre_ks_lwe_ser
        && wit.pre_ks_lwe_ser == wit.b4.pre_ks_lwe_ser
        && stmt.c_sgn_ser == wit.b4.c_sgn_ser
        && stmt.ctx.ctx_root == wit.b1.ctx_root
        && stmt.ctx.ctx_root == wit.b2.ctx_root
        && stmt.ctx.ctx_root == wit.b3.ctx_root
        && stmt.ctx.ctx_root == wit.b4.ctx_root
        && stmt.ctx.pbs_ks_id == wit.b4.pbs_ks_id
}
