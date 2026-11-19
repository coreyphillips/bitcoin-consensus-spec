// Bitcoin Core v32.1 proof-of-work functions (specification chapter 09) behind a small C ABI.
//
// As in oracle.cpp, nothing here implements consensus logic: arguments are decoded into Core's own
// types (arith_uint256, CBlockIndex, CBlockHeader, the networks' CChainParams) and Core's own
// functions are called. Every exported function catches every exception.

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>

namespace bcs_oracle {
// Defined in oracle.cpp.
int Fail(const char* what);
} // namespace bcs_oracle

namespace {

// Return codes, mirrored in src/ffi.rs.
constexpr int RC_TRUE = 1;
constexpr int RC_FALSE = 0;
constexpr int RC_BAD_NETWORK = -5;
constexpr int RC_BAD_CHAIN = -6;

// Network numbering of the C ABI, mirrored in src/ffi.rs.
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

// 32 bytes, big-endian, as GetHex prints them.
void WriteBigEndian(const arith_uint256& value, unsigned char* out32)
{
    const uint256 le = ArithToUint256(value);
    for (int i = 0; i < 32; ++i) out32[i] = le.data()[31 - i];
}

int Exception(const std::exception& e) { return bcs_oracle::Fail(e.what()); }

} // namespace

extern "C" {

// arith_uint256::SetCompact, GetCompact of the decoded value, and GetBitsProof.
int bcs_core_pow_compact(uint32_t bits, unsigned char* target32, int* negative, int* overflow,
                         uint32_t* compact, unsigned char* work32)
{
    try {
        arith_uint256 target;
        bool neg = false;
        bool ovf = false;
        target.SetCompact(bits, &neg, &ovf);
        WriteBigEndian(target, target32);
        *negative = neg ? 1 : 0;
        *overflow = ovf ? 1 : 0;
        *compact = target.GetCompact();
        WriteBigEndian(GetBitsProof(bits), work32);
        return RC_TRUE;
    } catch (const std::exception& e) {
        return Exception(e);
    } catch (...) {
        return bcs_oracle::Fail("unknown exception");
    }
}

// CheckProofOfWorkImpl, not CheckProofOfWork: the latter answers from a single hash bit in fuzz
// builds. `hash32` is in raw (little-endian) order.
int bcs_core_pow_check(int network, const unsigned char* hash32, uint32_t bits)
{
    try {
        const auto params = Params(network);
        if (!params) return RC_BAD_NETWORK;
        const uint256 hash{std::span<const unsigned char>{hash32, 32}};
        return CheckProofOfWorkImpl(hash, bits, params->GetConsensus()) ? RC_TRUE : RC_FALSE;
    } catch (const std::exception& e) {
        return Exception(e);
    } catch (...) {
        return bcs_oracle::Fail("unknown exception");
    }
}

// GetNextWorkRequired for a block with timestamp `time` whose parent is the last of `n` headers
// (times and bits given per header) at heights parent_height - n + 1 to parent_height. The window
// must start at the first block of the parent's difficulty period, which holds every header
// GetNextWorkRequired reads; a shorter or longer window is refused rather than guessed at.
int bcs_core_pow_next_work(int network, int32_t parent_height, size_t n, const uint32_t* times,
                           const uint32_t* bits, uint32_t time, uint32_t* out_bits)
{
    try {
        const auto params = Params(network);
        if (!params) return RC_BAD_NETWORK;
        const Consensus::Params& consensus = params->GetConsensus();
        const int64_t interval = consensus.DifficultyAdjustmentInterval();
        if (parent_height < 0 || n == 0 || static_cast<int64_t>(n) != parent_height % interval + 1) {
            return RC_BAD_CHAIN;
        }
        // CBlockIndex is neither copyable nor movable, so not a std::vector element.
        const std::unique_ptr<CBlockIndex[]> index{new CBlockIndex[n]};
        for (size_t i = 0; i < n; ++i) {
            index[i].nHeight = parent_height - static_cast<int32_t>(n - 1 - i);
            index[i].nTime = times[i];
            index[i].nBits = bits[i];
            // No skip pointers: BuildSkip would look below the window. GetAncestor then walks pprev.
            index[i].pprev = i == 0 ? nullptr : &index[i - 1];
        }
        CBlockHeader header;
        header.nTime = time;
        *out_bits = GetNextWorkRequired(&index[n - 1], &header, consensus);
        return RC_TRUE;
    } catch (const std::exception& e) {
        return Exception(e);
    } catch (...) {
        return bcs_oracle::Fail("unknown exception");
    }
}

} // extern "C"
