// Bitcoin Core v32.1 signet block solution check (specification chapter 13) behind a small C ABI.
//
// As in oracle.cpp, nothing here implements consensus logic: the block is deserialized into Core's
// CBlock, the network is Core's own SigNet parameters with the request's challenge, and Core's
// CheckSignetBlockSolution decides. Every exported function catches every exception.

#include <kernel/chainparams.h>
#include <primitives/block.h>
#include <serialize.h>
#include <signet.h>
#include <streams.h>

#include <cstdint>
#include <exception>
#include <span>
#include <vector>

namespace bcs_oracle {
// Defined in oracle.cpp.
int Fail(const char* what);
} // namespace bcs_oracle

namespace {

// Return codes, mirrored in src/ffi.rs.
constexpr int RC_TRUE = 1;
constexpr int RC_FALSE = 0;
constexpr int RC_BAD_BLOCK = -7;

} // namespace

extern "C" {

// CheckSignetBlockSolution on a signet whose challenge is the given script. A block that does not
// deserialize with witnesses, or leaves bytes over, is RC_BAD_BLOCK.
int bcs_core_signet_check(const unsigned char* block, size_t block_len, const unsigned char* challenge,
                          size_t challenge_len)
{
    try {
        CBlock parsed;
        try {
            SpanReader stream{std::span<const unsigned char>{block, block_len}};
            stream >> TX_WITH_WITNESS(parsed);
            if (!stream.empty()) return RC_BAD_BLOCK;
        } catch (const std::exception&) {
            return RC_BAD_BLOCK;
        }
        CChainParams::SigNetOptions options;
        options.challenge = std::vector<uint8_t>(challenge, challenge + challenge_len);
        const auto params = CChainParams::SigNet(options);
        return CheckSignetBlockSolution(parsed, params->GetConsensus()) ? RC_TRUE : RC_FALSE;
    } catch (const std::exception& e) {
        return bcs_oracle::Fail(e.what());
    } catch (...) {
        return bcs_oracle::Fail("unknown exception");
    }
}

} // extern "C"
