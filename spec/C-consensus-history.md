# Appendix C. Consensus history

This appendix is informative. It explains why the rules look the way they do: almost every quirk in Appendix A is the fossil of a historical bug fix or soft fork. Bitcoin's consensus rules have only ever been *tightened* (soft forks); no rule in this specification was ever relaxed, so every historical block that was valid when mined is still valid.

## C.1 Early fixes (2010 to 2012)

| When | Change | Effect on today's rules |
|---|---|---|
| 2010 | Signature script and output script run separately instead of concatenated (CVE-2010-5141, the "OP_RETURN" bug that let anyone spend any output). | Chapter 07 runs two scripts on one stack. |
| 2010 | Output value overflow (CVE-2010-5139: a block created 184 billion BTC). | `MoneyRange` checks on every output and every sum (chapter 08). |
| 2010 | Opcodes disabled (CVE-2010-5137 and related denial-of-service risks): `OP_CAT`, `OP_SUBSTR`, `OP_MUL` and others. | Disabled opcodes fail even when not executed (chapter 05); tapscript later reused them as `OP_SUCCESS`. |
| 2010 | Script size, element size, stack size and operation count limits. | The 10,000 / 520 / 1,000 / 201 limits of chapter 04. |
| 2010 | 1 MB block size limit. | Today the 4,000,000 weight limit; its non-witness part is still 1,000,000 bytes (chapter 10). |
| 2012 | BIP30: no transaction may overwrite an unspent output. Two earlier duplicate coinbases remain. | Chapter 10 section 10.7. |
| 2012 | BIP16 (pay-to-script-hash). One block mined during activation violates it. | Applied to all blocks except block 170060 (chapter 10 section 10.6). |
| 2012 | Merkle tree duplication (CVE-2012-2459). | Mutation detection and the `Mutated` failure kind (chapters 10, 11). |

## C.2 Version-number soft forks (2013 to 2015)

Each activated when 95% of recent blocks signalled a new block version; today they are *buried*: activated at a fixed height (chapter 12), with the block version floors as their remaining trace.

| BIP | Rule | Mainnet height |
|---|---|---|
| BIP34 | Coinbase starts with the block height; block version at least 2 | 227,931 |
| BIP66 | Strict DER signatures; version at least 3 | 363,725 |
| BIP65 | `OP_CHECKLOCKTIMEVERIFY`; version at least 4 | 388,381 |

## C.3 Version bits soft forks (2016 to 2021)

| BIPs | Rule | Mainnet height |
|---|---|---|
| BIP68, BIP112, BIP113 | Relative lock times, `OP_CHECKSEQUENCEVERIFY`, median time past for lock times | 419,328 |
| BIP141, BIP143, BIP147 | Segregated witness, the new signature hash, `NULLDUMMY` | 481,824 |
| BIP340, BIP341, BIP342 | Schnorr signatures, taproot, tapscript | 709,632 |

Bitcoin Core v32.0 stopped treating taproot as a deployment: its rules apply to every block except block 692261, which spent a taproot output before activation. CSV and segwit remain height-based, as listed in chapter 12.

## C.4 Later changes in Bitcoin Core that matter here

| Release | Change |
|---|---|
| 0.16 / 0.17 | P2SH and segwit rules applied to all historical blocks (except the exceptions) instead of from activation. |
| 0.16.3 | Duplicate inputs check restored in `CheckTransaction` (CVE-2018-17144). |
| 27 / 28 | Testnet4 with BIP94 (timewarp fix, difficulty from the first block of a period). |
| 28 | Network-adjusted time removed; the two-hour future limit uses the local clock. |
| 30 | Checkpoints removed. Script error for bad numbers became `SCRIPTNUM`. The `IsBlockMutated` pre-check used for blocks from peers. |
| 32 | Taproot removed as a deployment (buried). |

## C.5 Proposals that are not consensus

Bitcoin Core v32.1 contains code for some proposals that are **not** consensus rules, and implementations must not enforce them when validating blocks:

- BIP54 ("consensus cleanup"): v32.1 applies its 2,500 legacy sigop limit to transactions only as relay policy, and its timestamp and coinbase rules only when building block templates.
- The 64-byte transaction check exists only to detect mutated blocks from peers (chapter 11 section 11.11); 64-byte transactions are valid in blocks.
- Pay-to-anchor outputs are standard for relay since v28, but consensus treats them like any unknown witness program: anyone can spend them.
