// Bitcoin Core v32.1 consensus functions behind a small C ABI, for the conformance oracle.
//
// Nothing here implements consensus logic. Every function decodes its arguments into Core's own
// types and calls Core's own functions, then reports the result through plain integers.
//
// script/interpreter.cpp is compiled as part of this translation unit (it is not compiled
// separately by build.rs). SignatureHash and SignatureHashSchnorr are templates defined only in that
// file, and VerifyTaprootCommitment is a static function there. Including the file gives this code
// Core's own definitions of all three, so nothing is copied or re-implemented.
//
// Every exported function catches every exception: nothing may unwind into Rust.

#include <script/interpreter.cpp>

#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/script_error.h>
#include <span.h>
#include <streams.h>
#include <uint256.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <ios>
#include <span>
#include <string>
#include <vector>

namespace bcs_oracle {

// Return codes, mirrored in src/ffi.rs.
constexpr int RC_FALSE = 0;
constexpr int RC_TRUE = 1;
constexpr int RC_BAD_TX = -1;      // the transaction does not deserialize, or has trailing bytes
constexpr int RC_BAD_INDEX = -2;   // input index out of range
constexpr int RC_BAD_SPENT = -3;   // number of spent outputs differs from the number of inputs
constexpr int RC_BAD_FLAGS = -4;   // flag combination that VerifyScript does not accept
constexpr int RC_EXCEPTION = -100; // Core threw an exception

// Flag bits used on the C ABI (protocol order), mirrored in src/ffi.rs. They are translated to
// Core's own SCRIPT_VERIFY_* constants below, so no Core bit position is hard-coded.
constexpr uint32_t ABI_P2SH = 1u << 0;
constexpr uint32_t ABI_DERSIG = 1u << 1;
constexpr uint32_t ABI_NULLDUMMY = 1u << 2;
constexpr uint32_t ABI_CHECKLOCKTIMEVERIFY = 1u << 3;
constexpr uint32_t ABI_CHECKSEQUENCEVERIFY = 1u << 4;
constexpr uint32_t ABI_WITNESS = 1u << 5;
constexpr uint32_t ABI_TAPROOT = 1u << 6;
constexpr uint32_t ABI_ALL = (1u << 7) - 1;

thread_local std::string g_last_exception;

int Fail(const char* what)
{
    g_last_exception = what;
    return RC_EXCEPTION;
}

// Deserializes with witness allowed, exactly as Core reads a transaction from the network.
// Returns false on any decoding failure or when bytes remain after the transaction.
bool DecodeTx(const unsigned char* data, size_t len, CMutableTransaction& tx)
{
    try {
        SpanReader reader{std::span<const unsigned char>{data, len}};
        reader >> TX_WITH_WITNESS(tx);
        return reader.empty();
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<CTxOut> SpentOutputs(size_t n, const int64_t* amounts, const unsigned char* const* scripts, const size_t* lens)
{
    std::vector<CTxOut> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char* begin = scripts[i];
        out.emplace_back(CAmount{amounts[i]}, CScript(begin, begin + lens[i]));
    }
    return out;
}

// VerifyScript for input `index`, with a TransactionSignatureChecker over a
// PrecomputedTransactionData initialised with every spent output (as block validation does) and
// MissingDataBehavior::FAIL. The transaction has been decoded and the arguments checked.
int VerifyInput(const CMutableTransaction& mtx, uint32_t index, size_t n_spent, const int64_t* amounts,
                const unsigned char* const* scripts, const size_t* script_lens, script_verify_flags flags,
                int* script_error)
{
    // VerifyScript asserts these two flag dependencies.
    if ((flags & SCRIPT_VERIFY_WITNESS) && !(flags & SCRIPT_VERIFY_P2SH)) return RC_BAD_FLAGS;
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) && !((flags & SCRIPT_VERIFY_P2SH) && (flags & SCRIPT_VERIFY_WITNESS))) return RC_BAD_FLAGS;
    try {
        const CTransaction tx{mtx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, SpentOutputs(n_spent, amounts, scripts, script_lens));
        const CTxOut& spent = txdata.m_spent_outputs[index];
        const TransactionSignatureChecker checker{&tx, index, spent.nValue, txdata, MissingDataBehavior::FAIL};
        ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
        const bool ok = VerifyScript(tx.vin[index].scriptSig, spent.scriptPubKey, &tx.vin[index].scriptWitness, flags, checker, &err);
        *script_error = static_cast<int>(err);
        return ok ? RC_TRUE : RC_FALSE;
    } catch (const std::exception& e) {
        return Fail(e.what());
    } catch (...) {
        return Fail("unknown exception");
    }
}

void CopyString(const std::string& s, char* buf, size_t cap)
{
    if (cap == 0) return;
    const size_t n = s.size() < cap - 1 ? s.size() : cap - 1;
    std::memcpy(buf, s.data(), n);
    buf[n] = '\0';
}

} // namespace bcs_oracle

using namespace bcs_oracle;

extern "C" {

const char* bcs_core_last_exception()
{
    return g_last_exception.c_str();
}

// Script error identifiers. The names are those of the script_errors[] table in
// src/test/script_tests.cpp (the identifiers script_tests.json uses). Errors that table does not
// list use the ScriptError enumerator name without its SCRIPT_ERR_ prefix. The only difference
// between the two conventions is SCRIPT_ERR_SIG_NULLFAIL, which the table calls NULLFAIL.
const char* bcs_core_script_error_name(int code)
{
    switch (static_cast<ScriptError>(code)) {
    case SCRIPT_ERR_OK: return "OK";
    case SCRIPT_ERR_UNKNOWN_ERROR: return "UNKNOWN_ERROR";
    case SCRIPT_ERR_EVAL_FALSE: return "EVAL_FALSE";
    case SCRIPT_ERR_OP_RETURN: return "OP_RETURN";
    case SCRIPT_ERR_SCRIPTNUM: return "SCRIPTNUM";
    case SCRIPT_ERR_SCRIPT_SIZE: return "SCRIPT_SIZE";
    case SCRIPT_ERR_PUSH_SIZE: return "PUSH_SIZE";
    case SCRIPT_ERR_OP_COUNT: return "OP_COUNT";
    case SCRIPT_ERR_STACK_SIZE: return "STACK_SIZE";
    case SCRIPT_ERR_SIG_COUNT: return "SIG_COUNT";
    case SCRIPT_ERR_PUBKEY_COUNT: return "PUBKEY_COUNT";
    case SCRIPT_ERR_VERIFY: return "VERIFY";
    case SCRIPT_ERR_EQUALVERIFY: return "EQUALVERIFY";
    case SCRIPT_ERR_CHECKMULTISIGVERIFY: return "CHECKMULTISIGVERIFY";
    case SCRIPT_ERR_CHECKSIGVERIFY: return "CHECKSIGVERIFY";
    case SCRIPT_ERR_NUMEQUALVERIFY: return "NUMEQUALVERIFY";
    case SCRIPT_ERR_BAD_OPCODE: return "BAD_OPCODE";
    case SCRIPT_ERR_DISABLED_OPCODE: return "DISABLED_OPCODE";
    case SCRIPT_ERR_INVALID_STACK_OPERATION: return "INVALID_STACK_OPERATION";
    case SCRIPT_ERR_INVALID_ALTSTACK_OPERATION: return "INVALID_ALTSTACK_OPERATION";
    case SCRIPT_ERR_UNBALANCED_CONDITIONAL: return "UNBALANCED_CONDITIONAL";
    case SCRIPT_ERR_NEGATIVE_LOCKTIME: return "NEGATIVE_LOCKTIME";
    case SCRIPT_ERR_UNSATISFIED_LOCKTIME: return "UNSATISFIED_LOCKTIME";
    case SCRIPT_ERR_SIG_HASHTYPE: return "SIG_HASHTYPE";
    case SCRIPT_ERR_SIG_DER: return "SIG_DER";
    case SCRIPT_ERR_MINIMALDATA: return "MINIMALDATA";
    case SCRIPT_ERR_SIG_PUSHONLY: return "SIG_PUSHONLY";
    case SCRIPT_ERR_SIG_HIGH_S: return "SIG_HIGH_S";
    case SCRIPT_ERR_SIG_NULLDUMMY: return "SIG_NULLDUMMY";
    case SCRIPT_ERR_PUBKEYTYPE: return "PUBKEYTYPE";
    case SCRIPT_ERR_CLEANSTACK: return "CLEANSTACK";
    case SCRIPT_ERR_MINIMALIF: return "MINIMALIF";
    case SCRIPT_ERR_SIG_NULLFAIL: return "NULLFAIL";
    case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS: return "DISCOURAGE_UPGRADABLE_NOPS";
    case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: return "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM";
    case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: return "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION";
    case SCRIPT_ERR_DISCOURAGE_OP_SUCCESS: return "DISCOURAGE_OP_SUCCESS";
    case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: return "DISCOURAGE_UPGRADABLE_PUBKEYTYPE";
    case SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH: return "WITNESS_PROGRAM_WRONG_LENGTH";
    case SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY: return "WITNESS_PROGRAM_WITNESS_EMPTY";
    case SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH: return "WITNESS_PROGRAM_MISMATCH";
    case SCRIPT_ERR_WITNESS_MALLEATED: return "WITNESS_MALLEATED";
    case SCRIPT_ERR_WITNESS_MALLEATED_P2SH: return "WITNESS_MALLEATED_P2SH";
    case SCRIPT_ERR_WITNESS_UNEXPECTED: return "WITNESS_UNEXPECTED";
    case SCRIPT_ERR_WITNESS_PUBKEYTYPE: return "WITNESS_PUBKEYTYPE";
    case SCRIPT_ERR_SCHNORR_SIG_SIZE: return "SCHNORR_SIG_SIZE";
    case SCRIPT_ERR_SCHNORR_SIG_HASHTYPE: return "SCHNORR_SIG_HASHTYPE";
    case SCRIPT_ERR_SCHNORR_SIG: return "SCHNORR_SIG";
    case SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE: return "TAPROOT_WRONG_CONTROL_SIZE";
    case SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT: return "TAPSCRIPT_VALIDATION_WEIGHT";
    case SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG: return "TAPSCRIPT_CHECKMULTISIG";
    case SCRIPT_ERR_TAPSCRIPT_MINIMALIF: return "TAPSCRIPT_MINIMALIF";
    case SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY: return "TAPSCRIPT_EMPTY_PUBKEY";
    case SCRIPT_ERR_OP_CODESEPARATOR: return "OP_CODESEPARATOR";
    case SCRIPT_ERR_SIG_FINDANDDELETE: return "SIG_FINDANDDELETE";
    case SCRIPT_ERR_ERROR_COUNT: break;
    }
    return nullptr;
}

// The protocol's script_verify: VerifyScript for input `index` of `tx` under the consensus flags
// given as ABI bits.
int bcs_core_script_verify(const unsigned char* tx_data, size_t tx_len, uint32_t index,
                           size_t n_spent, const int64_t* amounts, const unsigned char* const* scripts,
                           const size_t* script_lens, uint32_t flag_bits, int* script_error)
{
    CMutableTransaction mtx;
    if (!DecodeTx(tx_data, tx_len, mtx)) return RC_BAD_TX;
    if (index >= mtx.vin.size()) return RC_BAD_INDEX;
    if (n_spent != mtx.vin.size()) return RC_BAD_SPENT;
    if ((flag_bits & ~ABI_ALL) != 0) return RC_BAD_FLAGS;
    script_verify_flags flags = SCRIPT_VERIFY_NONE;
    if (flag_bits & ABI_P2SH) flags |= SCRIPT_VERIFY_P2SH;
    if (flag_bits & ABI_DERSIG) flags |= SCRIPT_VERIFY_DERSIG;
    if (flag_bits & ABI_NULLDUMMY) flags |= SCRIPT_VERIFY_NULLDUMMY;
    if (flag_bits & ABI_CHECKLOCKTIMEVERIFY) flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    if (flag_bits & ABI_CHECKSEQUENCEVERIFY) flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    if (flag_bits & ABI_WITNESS) flags |= SCRIPT_VERIFY_WITNESS;
    if (flag_bits & ABI_TAPROOT) flags |= SCRIPT_VERIFY_TAPROOT;
    return VerifyInput(mtx, index, n_spent, amounts, scripts, script_lens, flags, script_error);
}

// Oracle extension, not part of PROTOCOL.md: the same as bcs_core_script_verify, but the flags are
// any of Core's flag names (ScriptFlagNamesToEnum), policy flags included. `bcs-conformance derive`
// uses it to replay Core's own tests with their original flags.
int bcs_core_script_verify_named(const unsigned char* tx_data, size_t tx_len, uint32_t index,
                                 size_t n_spent, const int64_t* amounts, const unsigned char* const* scripts,
                                 const size_t* script_lens, const char* const* names, size_t n_names,
                                 int* script_error)
{
    CMutableTransaction mtx;
    if (!DecodeTx(tx_data, tx_len, mtx)) return RC_BAD_TX;
    if (index >= mtx.vin.size()) return RC_BAD_INDEX;
    if (n_spent != mtx.vin.size()) return RC_BAD_SPENT;
    script_verify_flags flags = SCRIPT_VERIFY_NONE;
    const auto& by_name = ScriptFlagNamesToEnum();
    for (size_t i = 0; i < n_names; ++i) {
        const auto it = by_name.find(names[i]);
        if (it == by_name.end()) return RC_BAD_FLAGS;
        flags |= it->second;
    }
    return VerifyInput(mtx, index, n_spent, amounts, scripts, script_lens, flags, script_error);
}

// Deserialization (witness allowed, no trailing bytes) followed by CheckTransaction. On failure
// `reason` receives "tx-decode" or CheckTransaction's reject reason.
int bcs_core_tx_check(const unsigned char* tx_data, size_t tx_len, char* reason, size_t reason_cap)
{
    CMutableTransaction mtx;
    if (!DecodeTx(tx_data, tx_len, mtx)) {
        CopyString("tx-decode", reason, reason_cap);
        return RC_FALSE;
    }
    try {
        TxValidationState state;
        if (CheckTransaction(CTransaction{mtx}, state) && state.IsValid()) return RC_TRUE;
        CopyString(state.GetRejectReason(), reason, reason_cap);
        return RC_FALSE;
    } catch (const std::exception& e) {
        return Fail(e.what());
    } catch (...) {
        return Fail("unknown exception");
    }
}

// SignatureHash(scriptCode, tx, index, hashType, 0, SigVersion::BASE), as src/test/sighash_tests.cpp
// calls it. The 32 result bytes are written in raw order.
int bcs_core_sighash_legacy(const unsigned char* tx_data, size_t tx_len, const unsigned char* script,
                            size_t script_len, uint32_t index, int32_t hash_type, unsigned char* out32)
{
    CMutableTransaction mtx;
    if (!DecodeTx(tx_data, tx_len, mtx)) return RC_BAD_TX;
    if (index >= mtx.vin.size()) return RC_BAD_INDEX;
    try {
        const CTransaction tx{mtx};
        const CScript script_code(script, script + script_len);
        const uint256 hash = SignatureHash(script_code, tx, index, hash_type, 0, SigVersion::BASE);
        std::memcpy(out32, hash.data(), 32);
        return RC_TRUE;
    } catch (const std::exception& e) {
        return Fail(e.what());
    } catch (...) {
        return Fail("unknown exception");
    }
}

// SignatureHashSchnorr with a ScriptExecutionData filled from the arguments. Key path
// (SigVersion::TAPROOT) when leaf_hash is null, script path (SigVersion::TAPSCRIPT) otherwise.
// Returns RC_FALSE exactly when SignatureHashSchnorr fails.
int bcs_core_sighash_taproot(const unsigned char* tx_data, size_t tx_len, uint32_t index,
                             size_t n_spent, const int64_t* amounts, const unsigned char* const* scripts,
                             const size_t* script_lens, uint32_t hash_type, int has_annex,
                             const unsigned char* annex, size_t annex_len, const unsigned char* leaf_hash,
                             uint32_t codesep_pos, unsigned char* out32)
{
    CMutableTransaction mtx;
    if (!DecodeTx(tx_data, tx_len, mtx)) return RC_BAD_TX;
    if (index >= mtx.vin.size()) return RC_BAD_INDEX;
    if (n_spent != mtx.vin.size()) return RC_BAD_SPENT;
    if (hash_type > 0xff) return RC_BAD_FLAGS;
    try {
        const CTransaction tx{mtx};
        PrecomputedTransactionData txdata;
        // force=true precomputes the BIP341 data whatever the inputs look like, as the BIP341
        // test in src/test/script_tests.cpp does for unsigned transactions.
        txdata.Init(tx, SpentOutputs(n_spent, amounts, scripts, script_lens), /*force=*/true);

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = has_annex != 0;
        if (has_annex) {
            // As VerifyWitnessProgram computes it: SHA256 of the annex serialized with its length.
            const std::vector<unsigned char> annex_bytes(annex, annex + annex_len);
            execdata.m_annex_hash = (HashWriter{} << annex_bytes).GetSHA256();
        }
        SigVersion sigversion = SigVersion::TAPROOT;
        if (leaf_hash != nullptr) {
            sigversion = SigVersion::TAPSCRIPT;
            execdata.m_tapleaf_hash_init = true;
            execdata.m_tapleaf_hash = uint256{std::span<const unsigned char>{leaf_hash, 32}};
            execdata.m_codeseparator_pos_init = true;
            execdata.m_codeseparator_pos = codesep_pos;
        }
        uint256 hash;
        if (!SignatureHashSchnorr(hash, execdata, tx, index, static_cast<uint8_t>(hash_type), sigversion, txdata, MissingDataBehavior::FAIL)) {
            return RC_FALSE;
        }
        std::memcpy(out32, hash.data(), 32);
        return RC_TRUE;
    } catch (const std::exception& e) {
        return Fail(e.what());
    } catch (...) {
        return Fail("unknown exception");
    }
}

// The script path commitment check of VerifyWitnessProgram: the control block size rule, then
// the tapleaf hash and Core's VerifyTaprootCommitment.
int bcs_core_taproot_commitment_verify(const unsigned char* control_data, size_t control_len,
                                       const unsigned char* script, size_t script_len,
                                       const unsigned char* output_key32)
{
    try {
        if (control_len < TAPROOT_CONTROL_BASE_SIZE || control_len > TAPROOT_CONTROL_MAX_SIZE ||
            ((control_len - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) != 0) {
            return RC_FALSE;
        }
        const std::vector<unsigned char> control(control_data, control_data + control_len);
        const std::vector<unsigned char> program(output_key32, output_key32 + WITNESS_V1_TAPROOT_SIZE);
        const uint256 tapleaf_hash = ComputeTapleafHash(control[0] & TAPROOT_LEAF_MASK, std::span<const unsigned char>{script, script_len});
        return VerifyTaprootCommitment(control, program, tapleaf_hash) ? RC_TRUE : RC_FALSE;
    } catch (const std::exception& e) {
        return Fail(e.what());
    } catch (...) {
        return Fail("unknown exception");
    }
}

// BIP340 verification with Core's bundled libsecp256k1, for a message of any length.
int bcs_core_schnorr_verify(const unsigned char* pubkey32, const unsigned char* msg, size_t msg_len,
                            const unsigned char* sig64)
{
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &pubkey, pubkey32)) return RC_FALSE;
    return secp256k1_schnorrsig_verify(secp256k1_context_static, sig64, msg, msg_len, &pubkey) ? RC_TRUE : RC_FALSE;
}

} // extern "C"
