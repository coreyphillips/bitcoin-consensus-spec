# 07. Script verification

`verify_script` decides whether a transaction input may spend an output. It takes the input's signature script (`script_sig`) and witness, the spent output's `script_pubkey`, the flags in force, and the transaction context of chapter 05. It is the only entry point to the script system that later chapters use. (Core: `VerifyScript`, `src/script/interpreter.cpp`.)

## 7.1 The verification algorithm

1. Execute `script_sig` (`Base`) on an empty stack.
2. If `P2SH` is set, remember a copy of the resulting stack.
3. Execute `script_pubkey` (`Base`) on the same stack. The two scripts run one after the other on one stack; they are never concatenated (concatenation allowed spending anything in the early days of Bitcoin).
4. The stack must be non-empty and its top element true, else `EVAL_FALSE`.
5. **Native witness programs.** If `WITNESS` is set and `script_pubkey` is a witness program (chapter 04): `script_sig` must be exactly empty (else `WITNESS_MALLEATED`), and the witness program is verified (section 7.3).
6. **Pay-to-script-hash.** If `P2SH` is set and `script_pubkey` is the P2SH template:
   1. `script_sig` must be push-only (chapter 04, `is_push_only`), else `SIG_PUSHONLY`.
   2. The stack is replaced by the copy from step 2. Its top element is the *redeem script*; pop it and execute it (`Base`) on the rest. The stack must again be non-empty with a true top, else `EVAL_FALSE`.
   3. If `WITNESS` is set and the redeem script is a witness program, `script_sig` must be exactly the canonical push of the redeem script (`push_data(redeem_script)`, chapter 04), else `WITNESS_MALLEATED_P2SH`; then the witness program is verified with `is_p2sh = true`.
7. If `WITNESS` is set and no witness program was verified in steps 5 or 6, the input's witness must be empty, else `WITNESS_UNEXPECTED`.

Consequences that implementations get wrong:

- Step 4 applies to witness programs too: after `script_pubkey` runs, the top of the stack is the program itself, so a program that is all zero bytes (or negative zero) fails with `EVAL_FALSE` before the witness is even looked at, natively or inside P2SH.
- The P2SH output script `OP_HASH160 <20 bytes> OP_EQUAL` really executes in step 3, on the full stack left by `script_sig`. A `script_sig` that leaves 1000 elements therefore fails with `STACK_SIZE` when the hash is pushed.
- Redeem scripts are pushed by `script_sig`, so they are at most 520 bytes.
- The push-only check in step 6.1 happens only after both scripts have run, so a `script_sig` with other opcodes can fail earlier for a different reason. `OP_RESERVED` counts as push-only (executing it fails anyway).
- Only native (not P2SH-wrapped) version 1 programs of 32 bytes are taproot. A P2SH-wrapped version 1 program, or a version 1 program of any other length, is an unencumbered *future* program (section 7.3).

```rust
/// Core: `VerifyScript`.
pub fn verify_script(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptFlags, checker: &TxChecker) -> Result<(), ScriptError> {
    assert!((flags & VERIFY_WITNESS) == 0 || (flags & VERIFY_P2SH) != 0, "WITNESS requires P2SH");
    let mut had_witness = false;
    let mut stack: Vec<Vec<u8>> = Vec::new();

    eval_script(&mut stack, script_sig, flags, checker, SigVersion::Base, &mut ExecData::default())?;
    let stack_copy = if (flags & VERIFY_P2SH) != 0 { stack.clone() } else { Vec::new() };
    eval_script(&mut stack, script_pubkey, flags, checker, SigVersion::Base, &mut ExecData::default())?;
    if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
        return Err(ScriptError::EvalFalse);
    }

    if (flags & VERIFY_WITNESS) != 0 {
        if let Some((version, program)) = witness_program(script_pubkey) {
            had_witness = true;
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(witness, version, program, flags, checker, false)?;
        }
    }

    if (flags & VERIFY_P2SH) != 0 && is_p2sh(script_pubkey) {
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }
        let mut stack = stack_copy;
        // Non-empty: otherwise the P2SH script would have failed above.
        let redeem_script = stack.pop().expect("P2SH stack is not empty");
        eval_script(&mut stack, &redeem_script, flags, checker, SigVersion::Base, &mut ExecData::default())?;
        if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
            return Err(ScriptError::EvalFalse);
        }
        if (flags & VERIFY_WITNESS) != 0 {
            if let Some((version, program)) = witness_program(&redeem_script) {
                had_witness = true;
                if script_sig != push_data(&redeem_script).as_slice() {
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                verify_witness_program(witness, version, program, flags, checker, true)?;
            }
        }
    }

    if (flags & VERIFY_WITNESS) != 0 && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }
    Ok(())
}
```

## 7.2 Executing a witness script

Witness scripts (segwit version 0 scripts and tapscripts) run on the witness stack items, with two extra rules (Core: `ExecuteWitnessScript`):

- **Tapscript only, before anything else:** the script is scanned operation by operation. If an `OP_SUCCESSx` opcode (chapter 04) is found, the script *succeeds immediately* without being executed, regardless of everything else, including the stack limits below. If a malformed operation is found first, the script fails with `BAD_OPCODE`. Then, if the initial stack has more than 1000 items, it fails with `STACK_SIZE`.
- Every initial stack item must be at most 520 bytes, else `PUSH_SIZE`.
- After execution the stack must contain **exactly one** element (`CLEANSTACK`), which must be true (`EVAL_FALSE`). This "clean stack" rule is consensus for witness scripts, unlike for legacy scripts where it is only policy.

```rust
/// Core: `ExecuteWitnessScript`.
fn execute_witness_script(
    initial_stack: &[Vec<u8>],
    script: &[u8],
    flags: ScriptFlags,
    sigversion: SigVersion,
    checker: &TxChecker,
    execdata: &mut ExecData,
) -> Result<(), ScriptError> {
    let mut stack = initial_stack.to_vec();
    if sigversion == SigVersion::Tapscript {
        let mut pos = 0;
        while pos < script.len() {
            match get_op(script, &mut pos) {
                None => return Err(ScriptError::BadOpcode),
                Some(op) if is_op_success(op.opcode) => return Ok(()),
                Some(_) => {}
            }
        }
        if stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }
    if stack.iter().any(|item| item.len() > MAX_SCRIPT_ELEMENT_SIZE) {
        return Err(ScriptError::PushSize);
    }
    eval_script(&mut stack, script, flags, checker, sigversion, execdata)?;
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}
```

## 7.3 Witness programs

`verify_witness_program` dispatches on the version and program length (Core: `VerifyWitnessProgram`):

**Version 0, 32-byte program (pay-to-witness-script-hash).** The witness must have at least one item (else `WITNESS_PROGRAM_WITNESS_EMPTY`). The last item is the *witness script*; its **single** SHA-256 must equal the program (else `WITNESS_PROGRAM_MISMATCH`). The script runs (`WitnessV0`) on the remaining items. The witness script itself is not subject to the 520-byte item limit, but is subject to the 10,000-byte script size limit.

**Version 0, 20-byte program (pay-to-witness-public-key-hash).** The witness must have exactly two items (else `WITNESS_PROGRAM_MISMATCH`). The script `OP_DUP OP_HASH160 <program> OP_EQUALVERIFY OP_CHECKSIG` runs (`WitnessV0`) on them.

**Version 0, any other length:** fails with `WITNESS_PROGRAM_WRONG_LENGTH`.

**Version 1, 32-byte program, not inside P2SH (taproot).** Without the `TAPROOT` flag this is an unencumbered future program and succeeds. With it:

1. The witness must have at least one item, else `WITNESS_PROGRAM_WITNESS_EMPTY`.
2. If there are at least two items and the last one starts with `0x50`, it is the **annex**: remove it and remember `SHA256(var_bytes(annex))`. The annex has no other meaning yet.
3. **Key path**: if exactly one item remains, it is a signature, checked with `check_schnorr_signature` (`Taproot`) against the program as the public key. Any failure fails the input.
4. **Script path**: otherwise, the last remaining item is the *control block* and the one before it the *script*. The control block must be `33 + 32m` bytes with `0 <= m <= 128`, else `TAPROOT_WRONG_CONTROL_SIZE`. Its first byte holds the *leaf version* (`c[0] & 0xfe`) and the output key's y parity (`c[0] & 1`); the next 32 bytes are the internal key; the rest are the m merkle path nodes. The leaf hash is `tagged_hash("TapLeaf", leaf_version || var_bytes(script))`; walking the path, each step is `tagged_hash("TapBranch", min(k, node) || max(k, node))` with the two 32-byte strings ordered lexicographically. The commitment check of chapter 02 (`taproot_tweak_check`) must pass, else `WITNESS_PROGRAM_MISMATCH`.
5. With leaf version `0xc0` the script is a **tapscript**: the validation weight budget is set to the serialized witness size (the whole original witness, including annex, script and control block) plus 50, and the script runs as a witness script (`Tapscript`) on the remaining items.
6. Any other leaf version is reserved for future soft forks: the input **succeeds** without executing anything. This includes leaf versions that look odd, such as `0x50`.

**Version 1 with the two-byte program `4e 73`, not inside P2SH (pay-to-anchor):** succeeds.

**Any other version or length, or version 1 inside P2SH:** succeeds. These are reserved for future soft forks and are currently anyone-can-spend; the witness is not inspected.

```rust
/// Core: `WITNESS_V0_SCRIPTHASH_SIZE`, `WITNESS_V0_KEYHASH_SIZE`, `WITNESS_V1_TAPROOT_SIZE`.
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;
/// Core: `ANNEX_TAG`.
pub const ANNEX_TAG: u8 = 0x50;
/// Core: `TAPROOT_LEAF_MASK`, `TAPROOT_LEAF_TAPSCRIPT`.
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Core: `TAPROOT_CONTROL_BASE_SIZE`, `TAPROOT_CONTROL_NODE_SIZE`, `TAPROOT_CONTROL_MAX_NODE_COUNT`.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
pub const TAPROOT_CONTROL_MAX_SIZE: usize = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/// Core: `ComputeTapleafHash`.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> Hash256 {
    let mut data = vec![leaf_version];
    write_var_bytes(&mut data, script);
    tagged_hash("TapLeaf", &data)
}

/// Core: `ComputeTapbranchHash`.
pub fn tapbranch_hash(a: &[u8], b: &[u8]) -> Hash256 {
    let mut data = Vec::with_capacity(64);
    if a < b {
        data.extend_from_slice(a);
        data.extend_from_slice(b);
    } else {
        data.extend_from_slice(b);
        data.extend_from_slice(a);
    }
    tagged_hash("TapBranch", &data)
}

/// Core: `ComputeTaprootMerkleRoot`. The control block size has been checked by the caller.
pub fn taproot_merkle_root(control: &[u8], leaf_hash: &Hash256) -> Hash256 {
    let path_len = (control.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    let mut k = *leaf_hash;
    for i in 0..path_len {
        let start = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        k = tapbranch_hash(&k, &control[start..start + TAPROOT_CONTROL_NODE_SIZE]);
    }
    k
}

/// Core: `VerifyTaprootCommitment`.
pub fn verify_taproot_commitment(control: &[u8], program: &[u8], leaf_hash: &Hash256) -> bool {
    let internal_key = &control[1..TAPROOT_CONTROL_BASE_SIZE];
    let merkle_root = taproot_merkle_root(control, leaf_hash);
    taproot_tweak_check(&program[..32], (control[0] & 1) == 1, internal_key, &merkle_root)
}

/// True if the control block length is valid. Core: the size check in `VerifyWitnessProgram`.
pub fn control_block_size_valid(control: &[u8]) -> bool {
    control.len() >= TAPROOT_CONTROL_BASE_SIZE
        && control.len() <= TAPROOT_CONTROL_MAX_SIZE
        && (control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0
}

/// Serialized size of a witness stack: CompactSize count, then each item as var_bytes.
pub fn witness_serialized_size(witness: &[Vec<u8>]) -> usize {
    let mut size = compact_size_len(witness.len() as u64);
    for item in witness {
        size += compact_size_len(item.len() as u64) + item.len();
    }
    size
}

/// Core: `VerifyWitnessProgram`.
fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: ScriptFlags,
    checker: &TxChecker,
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    let mut execdata = ExecData::default();
    if version == 0 {
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            if witness.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let (script, stack) = witness.split_last().unwrap();
            if sha256(script)[..] != program[..] {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            execute_witness_script(stack, script, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else if program.len() == WITNESS_V0_KEYHASH_SIZE {
            if witness.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let mut script = vec![OP_DUP, OP_HASH160];
            script.extend_from_slice(&push_data(program));
            script.push(OP_EQUALVERIFY);
            script.push(OP_CHECKSIG);
            execute_witness_script(witness, &script, flags, SigVersion::WitnessV0, checker, &mut execdata)
        } else {
            Err(ScriptError::WitnessProgramWrongLength)
        }
    } else if version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        if (flags & VERIFY_TAPROOT) == 0 {
            return Ok(());
        }
        if witness.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }
        let mut stack: &[Vec<u8>] = witness;
        if stack.len() >= 2 {
            let last = &stack[stack.len() - 1];
            if !last.is_empty() && last[0] == ANNEX_TAG {
                let mut serialized = Vec::new();
                write_var_bytes(&mut serialized, last);
                execdata.annex_hash = Some(sha256(&serialized));
                stack = &stack[..stack.len() - 1];
            }
        }
        if stack.len() == 1 {
            // Key path spending.
            return checker.check_schnorr_signature(&stack[0], program, SigVersion::Taproot, &execdata);
        }
        // Script path spending.
        let control = &stack[stack.len() - 1];
        let script = &stack[stack.len() - 2];
        let stack = &stack[..stack.len() - 2];
        if !control_block_size_valid(control) {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        let leaf_version = control[0] & TAPROOT_LEAF_MASK;
        let leaf_hash = tapleaf_hash(leaf_version, script);
        if !verify_taproot_commitment(control, program, &leaf_hash) {
            return Err(ScriptError::WitnessProgramMismatch);
        }
        execdata.tapleaf_hash = Some(leaf_hash);
        if leaf_version == TAPROOT_LEAF_TAPSCRIPT {
            execdata.validation_weight_left = witness_serialized_size(witness) as i64 + VALIDATION_WEIGHT_OFFSET;
            return execute_witness_script(stack, script, flags, SigVersion::Tapscript, checker, &mut execdata);
        }
        // Unknown leaf version: reserved for future soft forks.
        Ok(())
    } else if !is_p2sh && is_pay_to_anchor(version, program) {
        Ok(())
    } else {
        // Unknown witness version or program length: reserved for future soft forks.
        Ok(())
    }
}
```

## 7.4 Verifying an input

Chapters 08 and 10 verify inputs through this convenience wrapper, which builds the transaction context and runs `verify_script`:

```rust
/// Verifies input `index` of `tx`, which spends `spent_outputs[index]`.
pub fn verify_input(tx: &Transaction, index: usize, spent_outputs: &[TxOut], precomputed: &PrecomputedTx, flags: ScriptFlags) -> Result<(), ScriptError> {
    let checker = TxChecker {
        tx,
        input_index: index,
        amount: spent_outputs[index].value,
        spent_outputs,
        precomputed,
    };
    let input = &tx.inputs[index];
    verify_script(&input.script_sig, &spent_outputs[index].script_pubkey, &input.witness, flags, &checker)
}
```
