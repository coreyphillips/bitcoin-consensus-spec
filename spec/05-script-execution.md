# 05. Script execution

This chapter defines `eval_script`, which executes one script on a stack. Chapter 07 combines executions into the full verification of a transaction input (signature script, output script, pay-to-script-hash, witness programs). Chapter 06 defines the signature hashes that signature-checking opcodes verify against.

Execution is identical across script versions except where this chapter says otherwise. The versions are:

| `SigVersion` | Used for |
|---|---|
| `Base` | Legacy scripts: signature scripts, output scripts, pay-to-script-hash redeem scripts |
| `WitnessV0` | BIP141 version 0 witness scripts (pay-to-witness-public-key-hash and pay-to-witness-script-hash) |
| `Taproot` | BIP341 key path spending (no script is executed) |
| `Tapscript` | BIP342 scripts in taproot script path spending |

## 5.1 Flags

Bitcoin Core passes a set of *script verification flags* into verification. Seven of them are consensus rules, switched on for blocks according to chapter 10. The others (`STRICTENC`, `LOW_S`, `MINIMALDATA`, `CLEANSTACK`, `NULLFAIL`, `MINIMALIF`, `WITNESS_PUBKEYTYPE`, `CONST_SCRIPTCODE`, `SIGPUSHONLY` and the `DISCOURAGE_*` family) exist only for transaction relay policy, are never set when validating blocks, and are not part of this specification. Code paths that only run under policy flags are omitted.

The bit positions match Bitcoin Core's so that flag sets can be compared numerically with its test data.

`WITNESS` is defined only together with `P2SH`: Bitcoin Core asserts this in `VerifyScript` and `CountWitnessSigOps`, and chapter 10 never produces `WITNESS` without `P2SH`. `TAPROOT` without `WITNESS` is allowed and has no effect.

```rust
/// A set of script verification flags (Core: `script_verify_flags`, `src/script/verify_flags.h`; the
/// flag names are in `src/script/interpreter.h`).
pub type ScriptFlags = u32;

/// BIP16 pay-to-script-hash.
pub const VERIFY_P2SH: ScriptFlags = 1 << 0;
/// BIP66 strict DER signature encoding.
pub const VERIFY_DERSIG: ScriptFlags = 1 << 2;
/// BIP147 the CHECKMULTISIG dummy element must be empty.
pub const VERIFY_NULLDUMMY: ScriptFlags = 1 << 4;
/// BIP65 OP_CHECKLOCKTIMEVERIFY.
pub const VERIFY_CHECKLOCKTIMEVERIFY: ScriptFlags = 1 << 9;
/// BIP112 OP_CHECKSEQUENCEVERIFY.
pub const VERIFY_CHECKSEQUENCEVERIFY: ScriptFlags = 1 << 10;
/// BIP141/BIP143 segregated witness.
pub const VERIFY_WITNESS: ScriptFlags = 1 << 11;
/// BIP341/BIP342 taproot and tapscript.
pub const VERIFY_TAPROOT: ScriptFlags = 1 << 17;

/// All consensus flags.
pub const CONSENSUS_FLAGS: ScriptFlags = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT;

/// Name of each consensus flag as used by Bitcoin Core's test data and the conformance protocol.
pub const FLAG_NAMES: [(&str, ScriptFlags); 7] = [
    ("P2SH", VERIFY_P2SH),
    ("DERSIG", VERIFY_DERSIG),
    ("NULLDUMMY", VERIFY_NULLDUMMY),
    ("CHECKLOCKTIMEVERIFY", VERIFY_CHECKLOCKTIMEVERIFY),
    ("CHECKSEQUENCEVERIFY", VERIFY_CHECKSEQUENCEVERIFY),
    ("WITNESS", VERIFY_WITNESS),
    ("TAPROOT", VERIFY_TAPROOT),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigVersion {
    Base,
    WitnessV0,
    Taproot,
    Tapscript,
}
```

## 5.2 Script errors

A failed script reports why. The identifiers are Bitcoin Core's (`src/script/script_error.h`) without the `SCRIPT_ERR_` prefix, as its test data writes them. Only errors that can occur under consensus flags are listed. As with block reject reasons (chapter 01), validity MUST match Bitcoin Core while the specific error SHOULD match; the reference reproduces Bitcoin Core's order of checks, so its errors match exactly.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptError {
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptNum,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    SigDer,
    SigPushOnly,
    SigNullDummy,
    CleanStack,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckmultisig,
    TapscriptMinimalif,
    TapscriptEmptyPubkey,
}

impl ScriptError {
    /// Identifier used by Bitcoin Core's test data and by the conformance protocol.
    pub fn name(&self) -> &'static str {
        match self {
            ScriptError::UnknownError => "UNKNOWN_ERROR",
            ScriptError::EvalFalse => "EVAL_FALSE",
            ScriptError::OpReturn => "OP_RETURN",
            ScriptError::ScriptNum => "SCRIPTNUM",
            ScriptError::ScriptSize => "SCRIPT_SIZE",
            ScriptError::PushSize => "PUSH_SIZE",
            ScriptError::OpCount => "OP_COUNT",
            ScriptError::StackSize => "STACK_SIZE",
            ScriptError::SigCount => "SIG_COUNT",
            ScriptError::PubkeyCount => "PUBKEY_COUNT",
            ScriptError::Verify => "VERIFY",
            ScriptError::EqualVerify => "EQUALVERIFY",
            ScriptError::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            ScriptError::CheckSigVerify => "CHECKSIGVERIFY",
            ScriptError::NumEqualVerify => "NUMEQUALVERIFY",
            ScriptError::BadOpcode => "BAD_OPCODE",
            ScriptError::DisabledOpcode => "DISABLED_OPCODE",
            ScriptError::InvalidStackOperation => "INVALID_STACK_OPERATION",
            ScriptError::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            ScriptError::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            ScriptError::NegativeLocktime => "NEGATIVE_LOCKTIME",
            ScriptError::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            ScriptError::SigDer => "SIG_DER",
            ScriptError::SigPushOnly => "SIG_PUSHONLY",
            ScriptError::SigNullDummy => "SIG_NULLDUMMY",
            ScriptError::CleanStack => "CLEANSTACK",
            ScriptError::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            ScriptError::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            ScriptError::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            ScriptError::WitnessMalleated => "WITNESS_MALLEATED",
            ScriptError::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            ScriptError::WitnessUnexpected => "WITNESS_UNEXPECTED",
            ScriptError::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            ScriptError::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            ScriptError::SchnorrSig => "SCHNORR_SIG",
            ScriptError::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            ScriptError::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            ScriptError::TapscriptCheckmultisig => "TAPSCRIPT_CHECKMULTISIG",
            ScriptError::TapscriptMinimalif => "TAPSCRIPT_MINIMALIF",
            ScriptError::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
        }
    }

    /// Bitcoin Core's description (`ScriptErrorString`), used inside block reject reasons (chapter 10).
    pub fn message(&self) -> &'static str {
        match self {
            ScriptError::UnknownError => "unknown error",
            ScriptError::EvalFalse => "Script evaluated without error but finished with a false/empty top stack element",
            ScriptError::OpReturn => "OP_RETURN was encountered",
            ScriptError::ScriptNum => "Script number overflowed or is non-minimally encoded",
            ScriptError::ScriptSize => "Script is too big",
            ScriptError::PushSize => "Push value size limit exceeded",
            ScriptError::OpCount => "Operation limit exceeded",
            ScriptError::StackSize => "Stack size limit exceeded",
            ScriptError::SigCount => "Signature count negative or greater than pubkey count",
            ScriptError::PubkeyCount => "Pubkey count negative or limit exceeded",
            ScriptError::Verify => "Script failed an OP_VERIFY operation",
            ScriptError::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            ScriptError::CheckMultisigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            ScriptError::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            ScriptError::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            ScriptError::BadOpcode => "Opcode missing or not understood",
            ScriptError::DisabledOpcode => "Attempted to use a disabled opcode",
            ScriptError::InvalidStackOperation => "Operation not valid with the current stack size",
            ScriptError::InvalidAltstackOperation => "Operation not valid with the current altstack size",
            ScriptError::UnbalancedConditional => "Invalid OP_IF construction",
            ScriptError::NegativeLocktime => "Negative locktime",
            ScriptError::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            ScriptError::SigDer => "Non-canonical DER signature",
            ScriptError::SigPushOnly => "Only push operators allowed in signatures",
            ScriptError::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            ScriptError::CleanStack => "Stack size must be exactly one after execution",
            ScriptError::WitnessProgramWrongLength => "Witness program has incorrect length",
            ScriptError::WitnessProgramWitnessEmpty => "Witness program was passed an empty witness",
            ScriptError::WitnessProgramMismatch => "Witness program hash mismatch",
            ScriptError::WitnessMalleated => "Witness requires empty scriptSig",
            ScriptError::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            ScriptError::WitnessUnexpected => "Witness provided for non-witness script",
            ScriptError::SchnorrSigSize => "Invalid Schnorr signature size",
            ScriptError::SchnorrSigHashtype => "Invalid Schnorr signature hash type",
            ScriptError::SchnorrSig => "Invalid Schnorr signature",
            ScriptError::TaprootWrongControlSize => "Invalid Taproot control block size",
            ScriptError::TapscriptValidationWeight => "Too much signature validation relative to witness weight",
            ScriptError::TapscriptCheckmultisig => "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
            ScriptError::TapscriptMinimalif => "OP_IF/NOTIF argument must be minimal in tapscript",
            ScriptError::TapscriptEmptyPubkey => "Empty public key in tapscript",
        }
    }
}

/// Script number decoding failures abort execution with `SCRIPTNUM`. Core: `catch (const scriptnum_error&)`.
fn script_num(bytes: &[u8], max_size: usize) -> Result<i64, ScriptError> {
    decode_script_num(bytes, false, max_size).map_err(|_| ScriptError::ScriptNum)
}
```

## 5.3 The transaction context

Signature checks and lock time checks need the spending transaction, the index of the input being verified, the amount of the output it spends, and (for taproot) every output spent by the transaction. `TxChecker` carries that context; `PrecomputedTx` holds per-transaction hashes used by the segwit signature hashes (chapter 06).

`ExecData` carries per-input state that taproot needs: whether an annex is present and its hash, the tapleaf hash, the position of the last executed `OP_CODESEPARATOR`, and the remaining *validation weight budget* (section 5.8). (Core: `ScriptExecutionData`.)

```rust
pub struct TxChecker<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
    /// Value of the output being spent by this input.
    pub amount: i64,
    /// The outputs spent by every input of `tx`, in input order.
    pub spent_outputs: &'a [TxOut],
    pub precomputed: &'a PrecomputedTx,
}

#[derive(Clone, Debug, Default)]
pub struct ExecData {
    /// SHA256 of the serialized annex, if the witness has one (chapter 07).
    pub annex_hash: Option<Hash256>,
    /// Tapleaf hash of the executing tapscript.
    pub tapleaf_hash: Option<Hash256>,
    /// Opcode position of the last executed OP_CODESEPARATOR, or 0xffffffff.
    pub codeseparator_pos: u32,
    /// Remaining tapscript validation weight budget.
    pub validation_weight_left: i64,
}
```

## 5.4 Lock time checks

`OP_CHECKLOCKTIMEVERIFY` (BIP65) succeeds only if the transaction's lock time is of the same kind as the operand (both block heights, below 500,000,000, or both times), is at least the operand, and the input's sequence is not `0xffffffff` (which would disable the transaction's lock time entirely, chapter 08).

`OP_CHECKSEQUENCEVERIFY` (BIP112) succeeds only if the transaction version is at least 2, **compared as an unsigned 32-bit integer** (so `0xffffffff` passes), the input's sequence does not have the disable bit (bit 31) set, and after masking both values to the type flag (bit 22) and the low 16 bits, they are of the same kind and the input's value is at least the operand's. (Core: `GenericTransactionSignatureChecker::CheckLockTime`, `CheckSequence`.) The disable bit of the *operand* is handled by the opcode before this check is reached (section 5.6).

```rust
/// Core: `CTxIn::SEQUENCE_FINAL`.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// Core: `CTxIn::SEQUENCE_LOCKTIME_MASK`.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

impl<'a> TxChecker<'a> {
    /// Core: `GenericTransactionSignatureChecker::CheckLockTime`.
    pub fn check_lock_time(&self, lock_time: i64) -> bool {
        let tx_lock_time = self.tx.lock_time as i64;
        let threshold = LOCKTIME_THRESHOLD as i64;
        if !((tx_lock_time < threshold && lock_time < threshold) || (tx_lock_time >= threshold && lock_time >= threshold)) {
            return false;
        }
        if lock_time > tx_lock_time {
            return false;
        }
        if self.tx.inputs[self.input_index].sequence == SEQUENCE_FINAL {
            return false;
        }
        true
    }

    /// Core: `GenericTransactionSignatureChecker::CheckSequence`.
    pub fn check_sequence(&self, sequence: i64) -> bool {
        let tx_sequence = self.tx.inputs[self.input_index].sequence as i64;
        if self.tx.version < 2 {
            return false;
        }
        if (tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64) != 0 {
            return false;
        }
        let mask = (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK) as i64;
        let tx_masked = tx_sequence & mask;
        let operand_masked = sequence & mask;
        let type_flag = SEQUENCE_LOCKTIME_TYPE_FLAG as i64;
        if !((tx_masked < type_flag && operand_masked < type_flag) || (tx_masked >= type_flag && operand_masked >= type_flag)) {
            return false;
        }
        operand_masked <= tx_masked
    }
}
```

## 5.5 Signature checks

### 5.5.1 ECDSA (Base and WitnessV0)

An ECDSA signature on the stack is a DER signature followed by one *hash type* byte. Checking it against a public key from the stack:

1. If the public key is not a valid key (chapter 02, `parse_pubkey`), the result is *false*.
2. If the signature is empty, the result is *false*.
3. The last byte is the hash type, used as an integer 0 to 255. Every value is allowed; undefined values behave as described in chapter 06.
4. In `WitnessV0`, a negative amount makes the result *false* (it cannot happen in a block).
5. The signature hash is computed for the script code (section 5.5.3) and the result is `ecdsa_verify` of chapter 02.

A *false* result is not an error: `OP_CHECKSIG` pushes false and execution continues. (Requiring failed signatures to be empty, `NULLFAIL`, is policy.)

Before the check, with `DERSIG` set, a **non-empty** signature must have strict DER encoding (`is_valid_signature_encoding` below, which includes the hash type byte), or the script fails with `SIG_DER`. An empty signature is always allowed, as a compact way to provide a signature that fails. The check constrains the form of R and S, not their size: a signature whose R or S has more than 32 significant bytes, or is not below the group order, passes it when otherwise well formed, and then fails verification because chapter 02's lax parser reads it as `(0, 0)`. The result is *false*, not an error. (Core: `CheckSignatureEncoding`, `IsValidSignatureEncoding`, `GenericTransactionSignatureChecker::CheckECDSASignature`.)

```rust
/// BIP66 strict DER encoding, including the trailing hash type byte.
/// Core: `IsValidSignatureEncoding`, `src/script/interpreter.cpp`.
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 || (sig[4] & 0x80) != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || (sig[len_r + 6] & 0x80) != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && (sig[len_r + 7] & 0x80) == 0 {
        return false;
    }
    true
}

impl<'a> TxChecker<'a> {
    /// Core: `GenericTransactionSignatureChecker::CheckECDSASignature`.
    pub fn check_ecdsa_signature(&self, sig: &[u8], pubkey: &[u8], script_code: &[u8], sigversion: SigVersion) -> bool {
        if parse_pubkey(pubkey).is_none() {
            return false;
        }
        if sig.is_empty() {
            return false;
        }
        let hash_type = sig[sig.len() - 1] as i32;
        let der = &sig[..sig.len() - 1];
        if sigversion == SigVersion::WitnessV0 && self.amount < 0 {
            return false;
        }
        let sighash = signature_hash(script_code, self.tx, self.input_index, hash_type, self.amount, sigversion, self.precomputed);
        ecdsa_verify(pubkey, der, &sighash)
    }
}
```

### 5.5.2 Schnorr (Taproot and Tapscript)

A taproot signature is 64 bytes (hash type `SIGHASH_DEFAULT`, 0) or 65 bytes (64 bytes plus an explicit hash type byte, which must not be 0). Any other size fails with `SCHNORR_SIG_SIZE`; an explicit 0 fails with `SCHNORR_SIG_HASHTYPE`; a hash type the signature hash rejects (chapter 06) fails with `SCHNORR_SIG_HASHTYPE`; an invalid signature fails with `SCHNORR_SIG`. Unlike ECDSA, every failure here aborts the script. The public key is the 32-byte x-only key. (Core: `GenericTransactionSignatureChecker::CheckSchnorrSignature`.)

```rust
impl<'a> TxChecker<'a> {
    /// Core: `GenericTransactionSignatureChecker::CheckSchnorrSignature`.
    pub fn check_schnorr_signature(&self, sig: &[u8], pubkey: &[u8], sigversion: SigVersion, execdata: &ExecData) -> Result<(), ScriptError> {
        assert!(pubkey.len() == 32);
        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::SchnorrSigSize);
        }
        let mut hash_type = 0u8;
        let mut sig = sig;
        if sig.len() == 65 {
            hash_type = sig[64];
            sig = &sig[..64];
            if hash_type == 0 {
                return Err(ScriptError::SchnorrSigHashtype);
            }
        }
        let sighash = match signature_hash_schnorr(execdata, self.tx, self.input_index, hash_type, sigversion, self.spent_outputs, self.precomputed) {
            Some(hash) => hash,
            None => return Err(ScriptError::SchnorrSigHashtype),
        };
        if !schnorr_verify(pubkey, &sighash, sig) {
            return Err(ScriptError::SchnorrSig);
        }
        Ok(())
    }
}
```

### 5.5.3 The script code

ECDSA signature hashes commit to a *script code*: the bytes of the executing script from just after the last executed `OP_CODESEPARATOR` (or from the start if none has executed) to the end. In `Base` only, every occurrence of the signature itself, encoded as a canonical push (`push_data(sig)`, chapter 04), is first removed from the script code with `find_and_delete` (chapter 06). For `OP_CHECKMULTISIG` every signature in the operation is removed before any of them is checked, so an *empty* signature among them removes every `OP_0` operation from the script code (a zero byte inside pushed data is not an operation and stays). (Core: `EvalChecksigPreTapscript`, the `OP_CHECKMULTISIG` case of `EvalScript`.)

### 5.5.4 Tapscript signature opcodes

In tapscript, `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` and `OP_CHECKSIGADD` follow BIP342, in exactly this order (Core: `EvalChecksigTapscript`):

1. The check *succeeds tentatively* if the signature is non-empty. A non-empty signature consumes 50 units of the validation weight budget (section 5.8); if the budget becomes negative, the script fails with `TAPSCRIPT_VALIDATION_WEIGHT`. This happens before the public key is looked at, so it also applies to unknown key types.
2. An empty public key fails the script with `TAPSCRIPT_EMPTY_PUBKEY`.
3. A 32-byte public key with a non-empty signature is checked with `check_schnorr_signature`; any failure aborts the script.
4. A public key of any other size is an *unknown key type*, reserved for future soft forks: no signature check happens and the tentative result stands.
5. The result is *true* if the signature was non-empty (and, for a 32-byte key, valid), *false* if the signature was empty.

```rust
/// Core: `EvalChecksigPreTapscript` (with policy flags omitted).
fn eval_checksig_pre_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    script_code_start: &[u8],
    flags: ScriptFlags,
    checker: &TxChecker,
    sigversion: SigVersion,
) -> Result<bool, ScriptError> {
    let mut script_code = script_code_start.to_vec();
    if sigversion == SigVersion::Base {
        script_code = find_and_delete(&script_code, &push_data(sig));
    }
    if (flags & VERIFY_DERSIG) != 0 && !sig.is_empty() && !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    Ok(checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion))
}

/// Core: `VALIDATION_WEIGHT_PER_SIGOP_PASSED`.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
/// Core: `VALIDATION_WEIGHT_OFFSET`.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Core: `EvalChecksigTapscript` (with policy flags omitted).
fn eval_checksig_tapscript(sig: &[u8], pubkey: &[u8], execdata: &mut ExecData, checker: &TxChecker) -> Result<bool, ScriptError> {
    let success = !sig.is_empty();
    if success {
        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if execdata.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }
    if pubkey.is_empty() {
        return Err(ScriptError::TapscriptEmptyPubkey);
    } else if pubkey.len() == 32 {
        if success {
            checker.check_schnorr_signature(sig, pubkey, SigVersion::Tapscript, execdata)?;
        }
    }
    Ok(success)
}
```

## 5.6 The interpreter

`eval_script` executes `script` on `stack` (which the caller supplies and inspects afterwards). It returns `Ok(())` or the first error. The alternate stack is local to one call: it starts empty for every script executed (signature script, output script, redeem script, witness script or tapscript), and nothing on it carries over to the next script. How the main stack passes from one script to the next is specified in chapter 07. The rules below are all implemented by the code that follows; they are listed because each one has been gotten wrong by some implementation.

**Before execution.** In `Base` and `WitnessV0`, a script longer than 10,000 bytes fails with `SCRIPT_SIZE`. Tapscript has no script size limit.

**For every operation, in this order:**

1. Whether the operation *executes* is decided first: it does if every enclosing `OP_IF`/`OP_NOTIF` branch is active.
2. The operation is parsed. A malformed operation fails with `BAD_OPCODE`, whether or not it would execute.
3. A push of more than 520 bytes fails with `PUSH_SIZE`, executed or not.
4. In `Base` and `WitnessV0`, every opcode above `OP_16` (so not pushes, `OP_1NEGATE`, `OP_RESERVED` or `OP_1`..`OP_16`) increments the operation counter, executed or not; more than 201 fails with `OP_COUNT`. `OP_CHECKMULTISIG` additionally adds its key count when it executes.
5. The disabled opcodes `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_2MUL`, `OP_2DIV`, `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT` and `OP_RSHIFT` fail with `DISABLED_OPCODE`, **even in a branch that is not executed**. (In tapscript these bytes are `OP_SUCCESS` opcodes and execution never starts; chapter 07.)
6. If the operation executes and is a data push (`OP_0` through `OP_PUSHDATA4`), the data is pushed.
7. Otherwise, if the operation executes, or is one of `OP_IF`, `OP_NOTIF`, `OP_VERIF`, `OP_VERNOTIF`, `OP_ELSE`, `OP_ENDIF` (bytes `0x63` to `0x68`, which are processed even in non-executing branches to track nesting), it is performed as described below. Any opcode without a definition fails with `BAD_OPCODE`. That includes `OP_VERIF` and `OP_VERNOTIF` (which therefore fail even in non-executing branches), and `OP_RESERVED`, `OP_VER`, `OP_RESERVED1`, `OP_RESERVED2`, `0xba` outside tapscript, and `0xbb` to `0xff` (which fail only when executed).
8. After the operation, if the main stack and the alternate stack together hold more than 1000 elements, the script fails with `STACK_SIZE`.

**After the last operation**, an unclosed `OP_IF`/`OP_NOTIF` fails with `UNBALANCED_CONDITIONAL`.

**Conditionals.** `OP_IF` and `OP_NOTIF` in an executing branch pop the top element and enter a branch that executes if the element is true (`OP_IF`) or false (`OP_NOTIF`), using `cast_to_bool`. In tapscript, the element must be empty or exactly `0x01`, otherwise `TAPSCRIPT_MINIMALIF`. In a non-executing branch they enter a non-executing branch without touching the stack. `OP_ELSE` toggles the innermost branch; `OP_ENDIF` closes it; both fail with `UNBALANCED_CONDITIONAL` outside any branch. `OP_ELSE` may appear several times in one branch, toggling each time.

**Numbers.** Arithmetic operands are decoded with `decode_script_num` limited to 4 bytes (5 for the lock time opcodes), never requiring minimal encoding. A failure is `SCRIPTNUM`. Results are pushed with `encode_script_num` and may be up to 5 bytes long.

**`OP_CODESEPARATOR`** (when executed) sets the script code start to just after itself, and records its *opcode position* (the zero-based index of the operation in the script, counting every operation including pushes) for tapscript signature hashes.

**Lock time opcodes.** Without their flag, `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` do nothing (they are `OP_NOP2` and `OP_NOP3`). With it, they need a stack element (else `INVALID_STACK_OPERATION`), decode it as a 5-byte number, and fail with `NEGATIVE_LOCKTIME` if it is negative. Only after that check, an `OP_CHECKSEQUENCEVERIFY` operand with bit 31 (the disable flag) set makes the operation succeed without the check of section 5.4; so `-1 OP_CHECKSEQUENCEVERIFY` fails with `NEGATIVE_LOCKTIME`, although -1 has bit 31 set as a 64-bit two's complement integer. Otherwise each fails with `UNSATISFIED_LOCKTIME` if the check of section 5.4 fails. Neither pops its operand.

**`OP_NOP1`, `OP_NOP4` to `OP_NOP10`** do nothing.

**Hash opcodes** replace the top element by its hash: `OP_RIPEMD160` (20 bytes), `OP_SHA1` (20), `OP_SHA256` (32), `OP_HASH160` (20), `OP_HASH256` (32).

**`OP_CHECKMULTISIG`** (not in tapscript, where it fails with `TAPSCRIPT_CHECKMULTISIG`) takes from the top: a key count n (0 to 20, else `PUBKEY_COUNT`), n public keys, a signature count m (0 to n, else `SIG_COUNT`), m signatures, and one more element, the *dummy*, which a historical bug consumes. Signatures are matched to keys from the top of the stack down: the last signature pushed (just below m) is checked first, against the last key pushed (just below n). A failed check moves to the next deeper key; a successful one moves to the next deeper signature and key. Each key is tried at most once, and as soon as more signatures remain than keys the result is false and the remaining signatures are not examined. With `DERSIG` the strict encoding check applies to a signature only when it is reached, so a badly encoded signature that is never reached does not fail the script. With `NULLDUMMY` the dummy must be empty, else `SIG_NULLDUMMY`.

**`OP_CHECKSIGADD`** (tapscript only; `BAD_OPCODE` elsewhere) takes a signature, a number n and a public key, and pushes n + 1 if the check succeeded or n if the signature was empty.

```rust
/// O(1) record of nested IF branches. Core: `ConditionStack`.
struct ConditionStack {
    size: usize,
    first_false: Option<usize>,
}

impl ConditionStack {
    fn new() -> ConditionStack {
        ConditionStack { size: 0, first_false: None }
    }
    fn is_empty(&self) -> bool {
        self.size == 0
    }
    fn all_true(&self) -> bool {
        self.first_false.is_none()
    }
    fn push(&mut self, value: bool) {
        if self.first_false.is_none() && !value {
            self.first_false = Some(self.size);
        }
        self.size += 1;
    }
    fn pop(&mut self) {
        self.size -= 1;
        if self.first_false == Some(self.size) {
            self.first_false = None;
        }
    }
    fn toggle_top(&mut self) {
        match self.first_false {
            None => self.first_false = Some(self.size - 1),
            Some(position) if position == self.size - 1 => self.first_false = None,
            Some(_) => {}
        }
    }
}

fn is_disabled_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD
            | OP_LSHIFT | OP_RSHIFT
    )
}

/// The element `depth` places from the top (1 is the top). The caller has checked the stack size.
fn top(stack: &[Vec<u8>], depth: usize) -> &Vec<u8> {
    &stack[stack.len() - depth]
}

fn bool_element(value: bool) -> Vec<u8> {
    if value {
        vec![1]
    } else {
        Vec::new()
    }
}

/// Executes `script` on `stack`. Core: `EvalScript`, `src/script/interpreter.cpp`.
pub fn eval_script(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    flags: ScriptFlags,
    checker: &TxChecker,
    sigversion: SigVersion,
    execdata: &mut ExecData,
) -> Result<(), ScriptError> {
    assert!(sigversion != SigVersion::Taproot);
    let legacy_limits = sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0;
    if legacy_limits && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    let mut pos = 0usize;
    let mut code_start = 0usize;
    let mut exec_stack = ConditionStack::new();
    let mut altstack: Vec<Vec<u8>> = Vec::new();
    let mut op_count = 0usize;
    let mut opcode_pos: u32 = 0;
    execdata.codeseparator_pos = 0xffff_ffff;

    while pos < script.len() {
        let executing = exec_stack.all_true();
        let op = match get_op(script, &mut pos) {
            Some(op) => op,
            None => return Err(ScriptError::BadOpcode),
        };
        let opcode = op.opcode;
        if op.data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if legacy_limits && opcode > OP_16 {
            op_count += 1;
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::OpCount);
            }
        }
        if is_disabled_opcode(opcode) {
            return Err(ScriptError::DisabledOpcode);
        }

        if executing && opcode <= OP_PUSHDATA4 {
            stack.push(op.data.to_vec());
        } else if executing || (OP_IF <= opcode && opcode <= OP_ENDIF) {
            match opcode {
                OP_1NEGATE | OP_1..=OP_16 => {
                    let value = opcode as i64 - (OP_1 as i64 - 1);
                    stack.push(encode_script_num(value));
                }

                OP_NOP => {}

                OP_CHECKLOCKTIMEVERIFY => {
                    if (flags & VERIFY_CHECKLOCKTIMEVERIFY) != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let lock_time = script_num(top(stack, 1), 5)?;
                        if lock_time < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if !checker.check_lock_time(lock_time) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_CHECKSEQUENCEVERIFY => {
                    if (flags & VERIFY_CHECKSEQUENCEVERIFY) != 0 {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let sequence = script_num(top(stack, 1), 5)?;
                        if sequence < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if (sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64) == 0 && !checker.check_sequence(sequence) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}

                OP_IF | OP_NOTIF => {
                    let mut value = false;
                    if executing {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let element = top(stack, 1);
                        if sigversion == SigVersion::Tapscript && (element.len() > 1 || (element.len() == 1 && element[0] != 1)) {
                            return Err(ScriptError::TapscriptMinimalif);
                        }
                        value = cast_to_bool(element);
                        if opcode == OP_NOTIF {
                            value = !value;
                        }
                        stack.pop();
                    }
                    exec_stack.push(value);
                }

                OP_ELSE => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    exec_stack.toggle_top();
                }

                OP_ENDIF => {
                    if exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    exec_stack.pop();
                }

                OP_VERIFY => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if cast_to_bool(top(stack, 1)) {
                        stack.pop();
                    } else {
                        return Err(ScriptError::Verify);
                    }
                }

                OP_RETURN => return Err(ScriptError::OpReturn),

                OP_TOALTSTACK => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    altstack.push(stack.pop().unwrap());
                }

                OP_FROMALTSTACK => {
                    if altstack.is_empty() {
                        return Err(ScriptError::InvalidAltstackOperation);
                    }
                    stack.push(altstack.pop().unwrap());
                }

                OP_2DROP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                    stack.pop();
                }

                OP_2DUP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 2).clone();
                    let b = top(stack, 1).clone();
                    stack.push(a);
                    stack.push(b);
                }

                OP_3DUP => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 3).clone();
                    let b = top(stack, 2).clone();
                    let c = top(stack, 1).clone();
                    stack.push(a);
                    stack.push(b);
                    stack.push(c);
                }

                OP_2OVER => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = top(stack, 4).clone();
                    let b = top(stack, 3).clone();
                    stack.push(a);
                    stack.push(b);
                }

                OP_2ROT => {
                    if stack.len() < 6 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    let a = stack[len - 6].clone();
                    let b = stack[len - 5].clone();
                    stack.drain(len - 6..len - 4);
                    stack.push(a);
                    stack.push(b);
                }

                OP_2SWAP => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 4, len - 2);
                    stack.swap(len - 3, len - 1);
                }

                OP_IFDUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    if cast_to_bool(&element) {
                        stack.push(element);
                    }
                }

                OP_DEPTH => {
                    let depth = stack.len() as i64;
                    stack.push(encode_script_num(depth));
                }

                OP_DROP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                }

                OP_DUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    stack.push(element);
                }

                OP_NIP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.remove(len - 2);
                }

                OP_OVER => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 2).clone();
                    stack.push(element);
                }

                OP_PICK | OP_ROLL => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    stack.pop();
                    if n < 0 || n >= stack.len() as i64 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let index = stack.len() - 1 - n as usize;
                    let element = stack[index].clone();
                    if opcode == OP_ROLL {
                        stack.remove(index);
                    }
                    stack.push(element);
                }

                OP_ROT => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 3, len - 2);
                    stack.swap(len - 2, len - 1);
                }

                OP_SWAP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 2, len - 1);
                }

                OP_TUCK => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = top(stack, 1).clone();
                    let len = stack.len();
                    stack.insert(len - 2, element);
                }

                OP_SIZE => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let size = top(stack, 1).len() as i64;
                    stack.push(encode_script_num(size));
                }

                OP_EQUAL | OP_EQUALVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let equal = top(stack, 2) == top(stack, 1);
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(equal));
                    if opcode == OP_EQUALVERIFY {
                        if equal {
                            stack.pop();
                        } else {
                            return Err(ScriptError::EqualVerify);
                        }
                    }
                }

                OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let result = match opcode {
                        OP_1ADD => n + 1,
                        OP_1SUB => n - 1,
                        OP_NEGATE => -n,
                        OP_ABS => n.abs(),
                        OP_NOT => (n == 0) as i64,
                        _ => (n != 0) as i64,
                    };
                    stack.pop();
                    stack.push(encode_script_num(result));
                }

                OP_ADD | OP_SUB | OP_BOOLAND | OP_BOOLOR | OP_NUMEQUAL | OP_NUMEQUALVERIFY | OP_NUMNOTEQUAL | OP_LESSTHAN
                | OP_GREATERTHAN | OP_LESSTHANOREQUAL | OP_GREATERTHANOREQUAL | OP_MIN | OP_MAX => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let a = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let b = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let result = match opcode {
                        OP_ADD => a + b,
                        OP_SUB => a - b,
                        OP_BOOLAND => (a != 0 && b != 0) as i64,
                        OP_BOOLOR => (a != 0 || b != 0) as i64,
                        OP_NUMEQUAL | OP_NUMEQUALVERIFY => (a == b) as i64,
                        OP_NUMNOTEQUAL => (a != b) as i64,
                        OP_LESSTHAN => (a < b) as i64,
                        OP_GREATERTHAN => (a > b) as i64,
                        OP_LESSTHANOREQUAL => (a <= b) as i64,
                        OP_GREATERTHANOREQUAL => (a >= b) as i64,
                        OP_MIN => a.min(b),
                        _ => a.max(b),
                    };
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(result));
                    if opcode == OP_NUMEQUALVERIFY {
                        if cast_to_bool(top(stack, 1)) {
                            stack.pop();
                        } else {
                            return Err(ScriptError::NumEqualVerify);
                        }
                    }
                }

                OP_WITHIN => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let x = script_num(top(stack, 3), DEFAULT_MAX_NUM_SIZE)?;
                    let min = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let max = script_num(top(stack, 1), DEFAULT_MAX_NUM_SIZE)?;
                    let within = min <= x && x < max;
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(within));
                }

                OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let element = stack.pop().unwrap();
                    let digest = match opcode {
                        OP_RIPEMD160 => ripemd160(&element).to_vec(),
                        OP_SHA1 => sha1(&element).to_vec(),
                        OP_SHA256 => sha256(&element).to_vec(),
                        OP_HASH160 => hash160(&element).to_vec(),
                        _ => sha256d(&element).to_vec(),
                    };
                    stack.push(digest);
                }

                OP_CODESEPARATOR => {
                    code_start = pos;
                    execdata.codeseparator_pos = opcode_pos;
                }

                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let sig = top(stack, 2).clone();
                    let pubkey = top(stack, 1).clone();
                    let success = if sigversion == SigVersion::Tapscript {
                        eval_checksig_tapscript(&sig, &pubkey, execdata, checker)?
                    } else {
                        eval_checksig_pre_tapscript(&sig, &pubkey, &script[code_start..], flags, checker, sigversion)?
                    };
                    stack.pop();
                    stack.pop();
                    stack.push(bool_element(success));
                    if opcode == OP_CHECKSIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckSigVerify);
                        }
                    }
                }

                OP_CHECKSIGADD => {
                    if sigversion != SigVersion::Tapscript {
                        return Err(ScriptError::BadOpcode);
                    }
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let sig = top(stack, 3).clone();
                    let n = script_num(top(stack, 2), DEFAULT_MAX_NUM_SIZE)?;
                    let pubkey = top(stack, 1).clone();
                    let success = eval_checksig_tapscript(&sig, &pubkey, execdata, checker)?;
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(n + success as i64));
                }

                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    if sigversion == SigVersion::Tapscript {
                        return Err(ScriptError::TapscriptCheckmultisig);
                    }
                    // `i` counts elements from the top, as in Bitcoin Core.
                    let mut i = 1usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut keys_count = script_num(top(stack, i), DEFAULT_MAX_NUM_SIZE)?;
                    if keys_count < 0 || keys_count > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::PubkeyCount);
                    }
                    op_count += keys_count as usize;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }
                    i += 1;
                    let mut ikey = i;
                    i += keys_count as usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut sigs_count = script_num(top(stack, i), DEFAULT_MAX_NUM_SIZE)?;
                    if sigs_count < 0 || sigs_count > keys_count {
                        return Err(ScriptError::SigCount);
                    }
                    i += 1;
                    let mut isig = i;
                    i += sigs_count as usize;
                    // The extra element counted here is the dummy.
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    let mut script_code = script[code_start..].to_vec();
                    for k in 0..sigs_count as usize {
                        let sig = top(stack, isig + k).clone();
                        if sigversion == SigVersion::Base {
                            script_code = find_and_delete(&script_code, &push_data(&sig));
                        }
                    }

                    let mut success = true;
                    while success && sigs_count > 0 {
                        let sig = top(stack, isig).clone();
                        let pubkey = top(stack, ikey).clone();
                        if (flags & VERIFY_DERSIG) != 0 && !sig.is_empty() && !is_valid_signature_encoding(&sig) {
                            return Err(ScriptError::SigDer);
                        }
                        if checker.check_ecdsa_signature(&sig, &pubkey, &script_code, sigversion) {
                            isig += 1;
                            sigs_count -= 1;
                        }
                        ikey += 1;
                        keys_count -= 1;
                        if sigs_count > keys_count {
                            success = false;
                        }
                    }

                    // Pop everything except the dummy.
                    for _ in 1..i {
                        stack.pop();
                    }
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if (flags & VERIFY_NULLDUMMY) != 0 && !top(stack, 1).is_empty() {
                        return Err(ScriptError::SigNullDummy);
                    }
                    stack.pop();
                    stack.push(bool_element(success));
                    if opcode == OP_CHECKMULTISIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckMultisigVerify);
                        }
                    }
                }

                _ => return Err(ScriptError::BadOpcode),
            }
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        opcode_pos += 1;
    }

    if !exec_stack.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}
```

Three details of the code above deserve attention:

- The opcode position used by `OP_CODESEPARATOR` advances only at the end of a completed operation, so the first operation is position 0, exactly as in Bitcoin Core's loop.
- `OP_PICK` and `OP_ROLL` require two elements before popping n, then require n to index the remaining stack.
- `OP_CHECKSIG` copies its two operands before popping them; `OP_CHECKMULTISIG` checks signatures against the stack in place and pops at the end, after the `NULLDUMMY` check of the dummy.

## 5.7 Arithmetic results

Operands are at most 4 bytes, so they lie in `-(2^31 - 1)` to `2^31 - 1`. Sums, differences, negations and absolute values of such operands are computed exactly in 64 bits and pushed even when they need 5 bytes. Such a result fails with `SCRIPTNUM` only if a later arithmetic opcode tries to read it.

## 5.8 Tapscript validation weight

Tapscript has no 201-operation limit and no script size limit. Instead, each input has a budget of `50 + (serialized size of its whole witness)`, where the serialized size counts the CompactSize item count and every item with its CompactSize length (the script, the control block and the annex included). Every signature opcode with a non-empty signature spends 50. The budget is set by chapter 07 before execution starts. (Core: `VerifyWitnessProgram`, `EvalChecksigTapscript`.)
