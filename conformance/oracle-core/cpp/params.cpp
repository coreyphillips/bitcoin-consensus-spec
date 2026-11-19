// Bitcoin Core v32.1 network parameters (specification chapter 12) behind a small C ABI.
//
// As in oracle.cpp, nothing here implements consensus logic: the values are read from Core's own
// CChainParams for the network and only formatted, as a JSON object in the field names of
// PROTOCOL.md's `network_params`. Every exported function catches every exception.

#include <kernel/chainparams.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace bcs_oracle {
// Defined in oracle.cpp.
int Fail(const char* what);
} // namespace bcs_oracle

namespace {

// Return codes, mirrored in src/ffi.rs.
constexpr int RC_TRUE = 1;
constexpr int RC_BAD_NETWORK = -5;

thread_local std::string g_params_json;

// Network numbering of the C ABI, as in pow.cpp.
std::unique_ptr<const CChainParams> Params(int network)
{
    switch (network) {
    case 0: return CChainParams::Main();
    case 1: return CChainParams::TestNet();
    case 2: return CChainParams::TestNet4();
    case 3: return CChainParams::SigNet();
    case 4: return CChainParams::RegTest();
    }
    return nullptr;
}

// The protocol's flag names. A flag outside them throws, so an exception Core adds later with a
// flag the protocol cannot name fails the request instead of being dropped.
std::string FlagNames(script_verify_flags flags)
{
    const std::pair<const char*, script_verify_flags> names[] = {
        {"P2SH", SCRIPT_VERIFY_P2SH},
        {"DERSIG", SCRIPT_VERIFY_DERSIG},
        {"NULLDUMMY", SCRIPT_VERIFY_NULLDUMMY},
        {"CHECKLOCKTIMEVERIFY", SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
        {"CHECKSEQUENCEVERIFY", SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
        {"WITNESS", SCRIPT_VERIFY_WITNESS},
        {"TAPROOT", SCRIPT_VERIFY_TAPROOT},
    };
    std::string out = "[";
    for (const auto& [name, flag] : names) {
        if (!(flags & flag)) continue;
        if (out.size() > 1) out += ",";
        out += "\"" + std::string{name} + "\"";
        flags &= ~flag;
    }
    if (flags) throw std::runtime_error("a script flag exception has a flag outside the protocol's");
    return out + "]";
}

std::string Quoted(const std::string& s) { return "\"" + s + "\""; }

std::string Json(const CChainParams& params)
{
    const Consensus::Params& c = params.GetConsensus();
    // Sorted by display hash, as PROTOCOL.md asks; Core's map is ordered by raw bytes.
    std::vector<std::pair<std::string, std::string>> exceptions;
    for (const auto& [hash, flags] : c.script_flag_exceptions) {
        exceptions.emplace_back(hash.GetHex(), FlagNames(flags));
    }
    std::sort(exceptions.begin(), exceptions.end());
    std::string list = "[";
    for (const auto& [hash, flags] : exceptions) {
        if (list.size() > 1) list += ",";
        list += "[" + Quoted(hash) + "," + flags + "]";
    }
    list += "]";
    const auto& start = params.MessageStart();
    auto field = [](const char* name, const std::string& value) { return "\"" + std::string{name} + "\":" + value; };
    auto boolean = [](bool b) { return std::string{b ? "true" : "false"}; };
    std::vector<std::string> fields = {
        field("genesis_hash", Quoted(c.hashGenesisBlock.GetHex())),
        field("subsidy_halving_interval", std::to_string(c.nSubsidyHalvingInterval)),
        field("bip34_height", std::to_string(c.BIP34Height)),
        field("bip34_hash", Quoted(c.BIP34Hash.GetHex())),
        field("bip65_height", std::to_string(c.BIP65Height)),
        field("bip66_height", std::to_string(c.BIP66Height)),
        field("csv_height", std::to_string(c.CSVHeight)),
        field("segwit_height", std::to_string(c.SegwitHeight)),
        field("pow_limit", Quoted(c.powLimit.GetHex())),
        field("pow_target_timespan", std::to_string(c.nPowTargetTimespan)),
        field("pow_target_spacing", std::to_string(c.nPowTargetSpacing)),
        field("pow_allow_min_difficulty_blocks", boolean(c.fPowAllowMinDifficultyBlocks)),
        field("pow_no_retargeting", boolean(c.fPowNoRetargeting)),
        field("enforce_bip94", boolean(c.enforce_BIP94)),
        field("script_flag_exceptions", list),
        field("signet_challenge", c.signet_blocks ? Quoted(HexStr(c.signet_challenge)) : "null"),
        field("message_start", Quoted(HexStr(std::span{start}))),
        field("default_port", std::to_string(params.GetDefaultPort())),
    };
    std::string out = "{";
    for (const auto& f : fields) {
        if (out.size() > 1) out += ",";
        out += f;
    }
    return out + "}";
}

} // namespace

extern "C" {

// The network's parameters as a JSON object, valid until the next call on this thread.
int bcs_core_network_params(int network, const char** json)
{
    try {
        const auto params = Params(network);
        if (!params) return RC_BAD_NETWORK;
        g_params_json = Json(*params);
        *json = g_params_json.c_str();
        return RC_TRUE;
    } catch (const std::exception& e) {
        return bcs_oracle::Fail(e.what());
    } catch (...) {
        return bcs_oracle::Fail("unknown exception");
    }
}

} // extern "C"
