# Appendix A. Quirks checklist

Every item below is a place where a natural implementation differs from Bitcoin Core, and where some implementation has in fact diverged. Each links to the normative definition. Use it as a review checklist: for every line, find the code in your implementation that handles it and the conformance test that covers it.

## Integers and encodings

| # | Quirk | Where |
|---|---|---|
| 1 | Transaction version is **unsigned**: BIP68 and `OP_CHECKSEQUENCEVERIFY` treat `0xffffffff` as at least 2. | 05 section 5.4, 08 section 8.6 |
| 2 | Block header version is **signed**: versions with the top bit set are negative and fail the version floors after BIP34. | 10 section 10.4 |
| 3 | CompactSize must be canonical and at most 33,554,432 when used as a length or count; violations are decode failures. | 03 section 3.1 |
| 4 | Input count 0 is read as the segwit marker; a following flag byte of 0 yields a transaction with **no inputs and no outputs** (10 bytes in total), which decodes and then fails `bad-txns-vin-empty`. | 03 section 3.2.2 |
| 5 | A witness flag with every witness stack empty is a decode failure ("Superfluous witness record"); flag bits other than bit 0 are a decode failure. | 03 section 3.2.2 |
| 6 | A witness stack with one empty item is a non-empty witness. | 03 section 3.2.1 |
| 7 | Bytes after the last transaction of a block are ignored. | 03 section 3.4 |
| 8 | Hashes are compared and stored in raw order; only display reverses them. Proof of work reads the hash as a little-endian number. | 01 section 1.4, 09 section 9.2 |

## Cryptography

| # | Quirk | Where |
|---|---|---|
| 9 | ECDSA signatures are parsed with the **lax** DER parser, even after BIP66; strict parsers decode some old signatures differently. | 02 section 2.8 |
| 10 | High-S ECDSA signatures are valid: S is normalized before verification. | 02 section 2.8 |
| 11 | Hybrid public keys (`0x06`, `0x07`) are valid when their parity byte matches. | 02 section 2.8 |
| 12 | An invalid public key makes `OP_CHECKSIG` push false; it does not fail the script (outside tapscript). | 05 section 5.5.1 |
| 13 | The legacy `SIGHASH_SINGLE` bug value is the bytes `01 00 .. 00`, used as the ECDSA message as is. | 06 section 6.2.3, 02 section 2.8 |
| 14 | The taproot tweak check fails (rather than panicking) when the tweak is at least the group order. | 02 section 2.10 |

## Script execution

| # | Quirk | Where |
|---|---|---|
| 15 | Disabled opcodes fail even in non-executed branches; `OP_VERIF` and `OP_VERNOTIF` too. | 05 section 5.6 |
| 16 | The 201-operation limit counts opcodes above `OP_16` in non-executed branches, plus CHECKMULTISIG key counts when executed. | 05 section 5.6 |
| 17 | The 520-byte push limit applies to pushes in non-executed branches. | 05 section 5.6 |
| 18 | The 1,000-element limit counts main plus alternate stack after **every** operation, including pushes. | 05 section 5.6 |
| 19 | Script numbers: 4-byte operands (5 for CLTV/CSV), non-minimal encodings accepted, negative zero is zero and false, results may be 5 bytes. | 04 sections 4.5 and 4.6 |
| 20 | Number decoding failures report `SCRIPTNUM` in Bitcoin Core v32.1, not `UNKNOWN_ERROR`. (Which release made this change cannot be confirmed from the v32.1 source tree.) | 05 section 5.2 |
| 21 | `CHECKMULTISIG` pops one extra element (the dummy); with `NULLDUMMY` it must be empty. | 05 section 5.6 |
| 22 | FindAndDelete removes the signature from the script code in legacy scripts only, at operation boundaries, repeatedly; an empty signature in CHECKMULTISIG removes every `OP_0` operation. | 06 section 6.2.1, 05 section 5.5.3 |
| 23 | Legacy sighash serializes the script code with `OP_CODESEPARATOR`s removed; BIP143 does not. | 06 sections 6.2.2, 6.3 |
| 24 | Any hash type byte is valid in legacy and BIP143 hashing, including 0 and undefined values. | 06 section 6.1 |
| 25 | In tapscript, `OP_SUCCESSx` anywhere in a parsable prefix makes the script succeed before any limit is checked; a parse error before it fails. | 07 section 7.2 |
| 26 | Tapscript `OP_IF` arguments must be empty or exactly `0x01`. | 05 section 5.6 |
| 27 | Tapscript: empty public key fails; unknown public key types (not 32 bytes) succeed; non-empty signatures spend validation weight even for unknown key types. | 05 section 5.5.4 |
| 28 | Tapscript validation budget is the serialized size of the **whole** witness (including annex, script, control block) plus 50. | 05 section 5.8, 07 section 7.3 |
| 29 | A 65-byte Schnorr signature with hash type 0 is invalid. | 05 section 5.5.2 |
| 30 | `OP_CODESEPARATOR` positions count every operation, starting at 0. | 05 section 5.6 |

## Script verification

| # | Quirk | Where |
|---|---|---|
| 31 | The P2SH output script is executed on the stack left by the signature script before the redeem script runs (a 1,000-element stack fails there). | 07 section 7.1 |
| 32 | A witness program that is false as a stack element (all bytes zero, or all zero except a final `0x80`, negative zero) is unspendable: `EVAL_FALSE` before witness checks. | 07 section 7.1, 04 section 4.6 |
| 33 | P2SH-wrapped witness programs need the signature script to be exactly the canonical push of the redeem script. | 07 section 7.1 |
| 34 | Only native version 1 programs of exactly 32 bytes are taproot; P2SH-wrapped version 1 and other lengths are anyone-can-spend. | 07 section 7.3 |
| 35 | Unknown witness versions, pay-to-anchor and unknown tapleaf versions (including `0x50`) succeed without executing anything. | 07 section 7.3 |
| 36 | The annex is the last item only if there are at least two items and it starts with `0x50`. | 07 section 7.3 |
| 37 | Witness data on an input that is not a witness program spend fails with `WITNESS_UNEXPECTED`. | 07 section 7.1 |
| 38 | Witness scripts must leave exactly one true element (clean stack is consensus there). | 07 section 7.2 |
| 39 | P2WSH uses single SHA-256 of the witness script; P2SH uses HASH160. | 07 section 7.3, 04 section 4.7 |

## Transactions and blocks

| # | Quirk | Where |
|---|---|---|
| 40 | Finality compares lock time with `<` against the block; CLTV compares with `<=` against the transaction. | 08 section 8.4 |
| 41 | BIP68 time locks use the median time past of the block **before** the coin's block, and of the parent of the including block; coins in the same block use the parent. | 08 section 8.6 |
| 42 | BIP113 uses the parent's median time past for finality only from the CSV height. | 10 section 10.5 |
| 43 | Coinbase maturity is `spend_height - coin_height >= 100`. | 08 section 8.7 |
| 44 | Duplicate inputs within one transaction are invalid (CVE-2018-17144). | 08 section 8.3 |
| 45 | Output scripts count toward the legacy sigop limit even though nothing executes them. | 08 section 8.8 |
| 46 | A P2SH spend counts 0 P2SH sigops if its signature script is malformed (for example a truncated push) or contains an operation above `OP_16`. Inside the redeem script, a malformed operation only stops counting and keeps the count so far. | 04 section 4.9 |
| 47 | Witness sigops are counted whenever the block's flags include `WITNESS`, which is nearly every block. | 08 section 8.8 |
| 48 | The sigop limit is inclusive: exactly 80,000 is valid. | 10 section 10.8 |
| 49 | Script flags apply per block, not per transaction: P2SH, WITNESS and TAPROOT for every block except the listed exceptions. | 10 section 10.6 |
| 50 | BIP34 encodes heights 1 to 16 as `OP_1`..`OP_16`, 0 as `OP_0`. | 10 section 10.5 |
| 51 | The witness commitment is the **last** matching coinbase output; the coinbase witness must then be exactly one 32-byte item. | 10 section 10.3 |
| 52 | Weight is checked after the witness commitment, so witness padding is `Mutated`, not `Invalid`. | 10 section 10.5 |
| 53 | BIP30 applies to all blocks except blocks 91842 and 91880 and (as an optimization) blocks below 1,983,702 on a chain with the BIP34 block; unspendable outputs never conflict. | 10 section 10.7 |
| 54 | Unspendable outputs (`OP_RETURN` first, or longer than 10,000 bytes) are never added to the UTXO set. | 10 section 10.8 |
| 55 | The genesis block's own coinbase output is not in the UTXO set. Its outpoint is not reserved: a byte-identical coinbase at height 486,604,799 would create it. | 10 section 10.8, 12 section 12.3 |
| 56 | Transactions are applied in order: a transaction can spend outputs of earlier transactions in the same block only. | 10 section 10.8 |
| 57 | The coinbase may claim less than allowed; it may not claim more. | 10 section 10.8 |

## Proof of work and headers

| # | Quirk | Where |
|---|---|---|
| 58 | Difficulty adjustment measures 2015 block intervals, not 2016. | 09 section 9.5 |
| 59 | `bits` must equal the computed value's canonical compact encoding exactly. | 09 section 9.1, 10 section 10.4 |
| 60 | Testnet minimum-difficulty rule depends on the new block's timestamp and walks back past minimum-difficulty blocks. | 09 section 9.5 |
| 61 | Testnet4 (BIP94) retargets from the period's **first** block's bits and limits timestamps at period starts. | 09 sections 9.5, 9.6 |
| 62 | Regtest allows minimum-difficulty blocks and never retargets. | 12 section 12.2 |
| 63 | Median time past takes the upper median of fewer than 11 blocks near genesis. | 09 section 9.4 |
| 64 | No checkpoints: Bitcoin Core v32.1 enforces none. (Which release removed them cannot be confirmed from the v32.1 source tree.) | 10 section 10.4 |
| 65 | Deployment heights can be overridden on every network except mainnet (testing). | 12 section 12.5 |

## Chain state

| # | Quirk | Where |
|---|---|---|
| 66 | Ties between equal-work chains go to the tip that became *linked* first; sequence numbers are assigned when a block and all ancestors have data, breadth first. | 11 sections 11.1, 11.6 |
| 67 | Mutated blocks, time-too-new headers and context-free body failures must not be recorded against the block hash. | 11 sections 11.1, 11.8 |
| 68 | Descendants of an invalid block are invalid, including ones learned later. | 11 sections 11.1, 11.5 and 11.6 |
| 69 | A failed reorganization may leave the node on its old chain or part way along the new one, whichever is the best valid chain. | 11 section 11.7 |
| 70 | Missing information is a failure, never a default value (fail closed). | 01 section 1.6 |
| 71 | Script check caches must be keyed by witness transaction id and flags, never by transaction id. | Appendix B |
| 72 | Request witness blocks (`MSG_WITNESS_BLOCK`), never plain blocks. | 14 section 14.4 |

## Found by reviewing other implementations

Each item below was found missing or wrong in another published consensus implementation or specification. The numbering continues so that earlier numbers stay stable.

| # | Quirk | Where |
|---|---|---|
| 73 | Signature operation counting has no 520-byte limit: a longer push, for example in an output script, does not stop the count; only a push that runs past the end of the script does. | 04 section 4.9 |
| 74 | The coinbase's legacy signature operations count toward the 80,000 cost when the block is connected, not only in the early legacy check. | 08 section 8.8, 10 section 10.8 |
| 75 | An ECDSA R or S that is not below the group order, or has more than 32 significant bytes, makes the signature parse as `(0, 0)`, which never verifies. It is never reduced modulo the order. | 02 section 2.8 |
| 76 | With `DERSIG`, a well-formed signature whose R or S is too large passes the encoding check; `OP_CHECKSIG` then returns false, it does not fail the script. | 05 section 5.5.1 |
| 77 | `OP_CHECKMULTISIG` checks a signature's encoding only when it reaches that signature, and stops as soon as more signatures remain than keys. | 05 section 5.6 |
| 78 | Transactions have no limit on their number of inputs or outputs other than the size rule. | 08 section 8.3 |
| 79 | A P2SH redeem script is pushed by the signature script, so one over 520 bytes can never be spent. Code that parses the pushes itself must keep the limit. | 07 section 7.1 |
