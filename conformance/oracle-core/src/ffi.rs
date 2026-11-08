//! Safe wrappers around the C ABI exported by `cpp/oracle.cpp`.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

// Return codes of cpp/oracle.cpp.
const RC_FALSE: c_int = 0;
const RC_TRUE: c_int = 1;
const RC_BAD_TX: c_int = -1;
const RC_BAD_INDEX: c_int = -2;
const RC_BAD_SPENT: c_int = -3;
const RC_BAD_FLAGS: c_int = -4;
const RC_EXCEPTION: c_int = -100;

/// Flag bits of the C ABI, in protocol order (cpp/oracle.cpp maps them to Core's constants).
pub const FLAG_NAMES: [&str; 7] = [
    "P2SH",
    "DERSIG",
    "NULLDUMMY",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "TAPROOT",
];

extern "C" {
    fn bcs_core_last_exception() -> *const c_char;
    fn bcs_core_script_error_name(code: c_int) -> *const c_char;
    fn bcs_core_script_verify(
        tx: *const u8,
        tx_len: usize,
        index: u32,
        n_spent: usize,
        amounts: *const i64,
        scripts: *const *const u8,
        script_lens: *const usize,
        flags: u32,
        script_error: *mut c_int,
    ) -> c_int;
    fn bcs_core_script_verify_named(
        tx: *const u8,
        tx_len: usize,
        index: u32,
        n_spent: usize,
        amounts: *const i64,
        scripts: *const *const u8,
        script_lens: *const usize,
        names: *const *const c_char,
        n_names: usize,
        script_error: *mut c_int,
    ) -> c_int;
    fn bcs_core_tx_check(
        tx: *const u8,
        tx_len: usize,
        reason: *mut c_char,
        reason_cap: usize,
    ) -> c_int;
    fn bcs_core_sighash_legacy(
        tx: *const u8,
        tx_len: usize,
        script: *const u8,
        script_len: usize,
        index: u32,
        hash_type: i32,
        out32: *mut u8,
    ) -> c_int;
    fn bcs_core_sighash_taproot(
        tx: *const u8,
        tx_len: usize,
        index: u32,
        n_spent: usize,
        amounts: *const i64,
        scripts: *const *const u8,
        script_lens: *const usize,
        hash_type: u32,
        has_annex: c_int,
        annex: *const u8,
        annex_len: usize,
        leaf_hash: *const u8,
        codesep_pos: u32,
        out32: *mut u8,
    ) -> c_int;
    fn bcs_core_taproot_commitment_verify(
        control: *const u8,
        control_len: usize,
        script: *const u8,
        script_len: usize,
        output_key32: *const u8,
    ) -> c_int;
    fn bcs_core_schnorr_verify(
        pubkey32: *const u8,
        msg: *const u8,
        msg_len: usize,
        sig64: *const u8,
    ) -> c_int;
}

/// Why a call into Core could not produce a result.
#[derive(Debug)]
pub enum CoreError {
    /// The request was malformed (the protocol's `bad_request`).
    BadRequest(String),
    /// Core threw an exception or returned something unexpected (the protocol's `internal`).
    Internal(String),
}

fn last_exception() -> String {
    // SAFETY: the C++ side returns a pointer to a thread-local NUL-terminated string.
    unsafe { CStr::from_ptr(bcs_core_last_exception()) }
        .to_string_lossy()
        .into_owned()
}

fn rc_to_bool(rc: c_int) -> Result<bool, CoreError> {
    match rc {
        RC_TRUE => Ok(true),
        RC_FALSE => Ok(false),
        RC_BAD_TX => Err(CoreError::BadRequest(
            "transaction does not deserialize or has trailing bytes".into(),
        )),
        RC_BAD_INDEX => Err(CoreError::BadRequest("input index out of range".into())),
        RC_BAD_SPENT => Err(CoreError::BadRequest(
            "spent_outputs must have one entry per transaction input".into(),
        )),
        RC_BAD_FLAGS => Err(CoreError::BadRequest(
            "unknown flag, or a combination VerifyScript does not accept (WITNESS requires P2SH, CLEANSTACK requires P2SH and WITNESS)".into(),
        )),
        RC_EXCEPTION => Err(CoreError::Internal(format!("Bitcoin Core threw: {}", last_exception()))),
        other => Err(CoreError::Internal(format!("unexpected return code {other}"))),
    }
}

/// One spent output: amount in satoshis and scriptPubKey.
pub struct SpentOutput {
    pub amount: i64,
    pub script_pubkey: Vec<u8>,
}

struct SpentArrays {
    amounts: Vec<i64>,
    ptrs: Vec<*const u8>,
    lens: Vec<usize>,
}

fn spent_arrays(spent: &[SpentOutput]) -> SpentArrays {
    SpentArrays {
        amounts: spent.iter().map(|s| s.amount).collect(),
        ptrs: spent.iter().map(|s| s.script_pubkey.as_ptr()).collect(),
        lens: spent.iter().map(|s| s.script_pubkey.len()).collect(),
    }
}

/// `VerifyScript` result: validity and the script error identifier.
pub fn script_verify(
    tx: &[u8],
    index: u32,
    spent: &[SpentOutput],
    flags: u32,
) -> Result<(bool, String), CoreError> {
    let arrays = spent_arrays(spent);
    let mut err: c_int = -1;
    // SAFETY: every pointer/length pair describes a live Rust buffer for the duration of the call.
    let rc = unsafe {
        bcs_core_script_verify(
            tx.as_ptr(),
            tx.len(),
            index,
            spent.len(),
            arrays.amounts.as_ptr(),
            arrays.ptrs.as_ptr(),
            arrays.lens.as_ptr(),
            flags,
            &mut err,
        )
    };
    let valid = rc_to_bool(rc)?;
    Ok((valid, script_error_name(err)?))
}

fn script_error_name(err: c_int) -> Result<String, CoreError> {
    // SAFETY: returns either NULL or a pointer to a static NUL-terminated string.
    let name = unsafe { bcs_core_script_error_name(err) };
    if name.is_null() {
        return Err(CoreError::Internal(format!(
            "unknown ScriptError value {err}"
        )));
    }
    Ok(unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned())
}

/// Oracle extension: `VerifyScript` with any of Core's flag names (policy flags included).
pub fn script_verify_named(
    tx: &[u8],
    index: u32,
    spent: &[SpentOutput],
    names: &[String],
) -> Result<(bool, String), CoreError> {
    let arrays = spent_arrays(spent);
    let c_names: Vec<std::ffi::CString> = names
        .iter()
        .map(|n| std::ffi::CString::new(n.as_str()))
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::BadRequest("flag name contains NUL".into()))?;
    let ptrs: Vec<*const c_char> = c_names.iter().map(|c| c.as_ptr()).collect();
    let mut err: c_int = -1;
    // SAFETY: every pointer/length pair describes a live buffer for the duration of the call.
    let rc = unsafe {
        bcs_core_script_verify_named(
            tx.as_ptr(),
            tx.len(),
            index,
            spent.len(),
            arrays.amounts.as_ptr(),
            arrays.ptrs.as_ptr(),
            arrays.lens.as_ptr(),
            ptrs.as_ptr(),
            ptrs.len(),
            &mut err,
        )
    };
    let valid = rc_to_bool(rc)?;
    Ok((valid, script_error_name(err)?))
}

/// Deserialization plus `CheckTransaction`. Returns the reject reason when invalid.
pub fn tx_check(tx: &[u8]) -> Result<Option<String>, CoreError> {
    let mut buf = [0 as c_char; 256];
    // SAFETY: the buffer outlives the call and its capacity is passed.
    let rc = unsafe { bcs_core_tx_check(tx.as_ptr(), tx.len(), buf.as_mut_ptr(), buf.len()) };
    if rc_to_bool(rc)? {
        Ok(None)
    } else {
        let reason = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Ok(Some(reason))
    }
}

/// Legacy `SignatureHash` (SigVersion::BASE, amount 0). Raw byte order.
pub fn sighash_legacy(
    tx: &[u8],
    script_code: &[u8],
    index: u32,
    hash_type: i32,
) -> Result<[u8; 32], CoreError> {
    let mut out = [0u8; 32];
    // SAFETY: all buffers are live for the call; out has room for 32 bytes.
    let rc = unsafe {
        bcs_core_sighash_legacy(
            tx.as_ptr(),
            tx.len(),
            script_code.as_ptr(),
            script_code.len(),
            index,
            hash_type,
            out.as_mut_ptr(),
        )
    };
    if rc_to_bool(rc)? {
        Ok(out)
    } else {
        Err(CoreError::Internal("SignatureHash reported failure".into()))
    }
}

/// `SignatureHashSchnorr`. `None` when Core's function fails. Raw byte order.
#[allow(clippy::too_many_arguments)]
pub fn sighash_taproot(
    tx: &[u8],
    index: u32,
    spent: &[SpentOutput],
    hash_type: u32,
    annex: Option<&[u8]>,
    leaf_hash: Option<&[u8; 32]>,
    codesep_pos: u32,
) -> Result<Option<[u8; 32]>, CoreError> {
    let arrays = spent_arrays(spent);
    let mut out = [0u8; 32];
    let (has_annex, annex_ptr, annex_len) = match annex {
        Some(a) => (1, a.as_ptr(), a.len()),
        None => (0, std::ptr::null(), 0),
    };
    let leaf_ptr = leaf_hash.map_or(std::ptr::null(), |h| h.as_ptr());
    // SAFETY: all buffers are live for the call; out has room for 32 bytes.
    let rc = unsafe {
        bcs_core_sighash_taproot(
            tx.as_ptr(),
            tx.len(),
            index,
            spent.len(),
            arrays.amounts.as_ptr(),
            arrays.ptrs.as_ptr(),
            arrays.lens.as_ptr(),
            hash_type,
            has_annex,
            annex_ptr,
            annex_len,
            leaf_ptr,
            codesep_pos,
            out.as_mut_ptr(),
        )
    };
    Ok(if rc_to_bool(rc)? { Some(out) } else { None })
}

/// Control block size rule plus `VerifyTaprootCommitment`.
pub fn taproot_commitment_verify(
    control: &[u8],
    script: &[u8],
    output_key: &[u8; 32],
) -> Result<bool, CoreError> {
    // SAFETY: all buffers are live for the call.
    let rc = unsafe {
        bcs_core_taproot_commitment_verify(
            control.as_ptr(),
            control.len(),
            script.as_ptr(),
            script.len(),
            output_key.as_ptr(),
        )
    };
    rc_to_bool(rc)
}

/// BIP340 verification through Core's bundled libsecp256k1.
pub fn schnorr_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<bool, CoreError> {
    // SAFETY: all buffers are live for the call.
    let rc =
        unsafe { bcs_core_schnorr_verify(pubkey.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) };
    rc_to_bool(rc)
}
