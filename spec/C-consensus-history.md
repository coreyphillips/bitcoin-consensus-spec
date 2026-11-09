# Appendix C. Consensus history

This appendix is informative. It explains why the rules look the way they do: almost every quirk in Appendix A is the fossil of a historical bug fix or soft fork. Almost every change to Bitcoin's consensus rules has *tightened* them (soft forks), and each was arranged so that the blocks of the main chain stay valid; the exceptions in chapter 10 exist for that reason. Relaxations have been rare. In 2013, releases up to 0.7.2 turned out to reject some valid blocks because of a database lock limit; 0.8.1 added a temporary rule to stay compatible with them, and the limit was then dropped (BIP50). The removal of checkpoints also relaxed which forks a node accepts (Appendix A item 64). Blocks that were accepted only because of a bug, such as the 2010 value overflow block, are invalid under today's rules and are not part of the main chain.

Release attributions below are to the release that *first* shipped a change, checked against the release notes and `doc/bips.md` in the Bitcoin Core v32.1 source tree. The 2010 rows of C.1 cannot be checked against that tree; where a row names a CVE, the public vulnerability record is its source.

## C.1 Early fixes (2010 to 2012)

| When | Change | Effect on today's rules |
|---|---|---|
| 2010 | `OP_RETURN` could end a concatenated signature script and output script with a true value, letting anyone spend any output (CVE-2010-5141). It was fixed in 2010, and a later change went further and ran the signature script and the output script separately instead of concatenated. | Chapter 07 runs two scripts on one stack. |
| 2010 | Output value overflow (CVE-2010-5139: a block created 184 billion BTC). | `MoneyRange` checks on every output and every sum (chapter 08). |
| 2010 | Opcodes disabled (CVE-2010-5137 and related denial-of-service risks): `OP_CAT`, `OP_SUBSTR`, `OP_MUL` and others. | Disabled opcodes fail even when not executed (chapter 05); tapscript later reused them as `OP_SUCCESS`. |
| 2010 | Script size, element size, stack size and operation count limits. | The 10,000 / 520 / 1,000 / 201 limits of chapter 04. |
| 2010 | 1 MB block size limit. | Today the 4,000,000 weight limit; its non-witness part is still 1,000,000 bytes (chapter 10). |
| 2012 | BIP30: no transaction may overwrite an unspent output (first released in 0.6.0, in force from March 15th 2012). Two earlier duplicate coinbases remain. | Chapter 10 section 10.7. |
| 2012 | BIP16 (pay-to-script-hash; first released in 0.6.0, in force from April 1st 2012). One block mined during activation violates it. | Applied to all blocks except block 170060 (chapter 10 section 10.6). |
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

Since Bitcoin Core 24.0, taproot's rules apply to every block except block 692261, the one historical block that violates them, which is validated without them. Bitcoin Core v32.1 only removed the `taproot` entry from the `getdeploymentinfo` RPC, with no effect on validation (32.0 was tagged but never fully released). CSV and segwit remain height-based, as listed in chapter 12.

## C.4 Later changes in Bitcoin Core that matter here

| First released in | Change |
|---|---|
| 0.16.3 | Duplicate inputs check restored in `CheckTransaction` (CVE-2018-17144; #14249). |
| 0.17.0 | P2SH and segwit rules applied to all historical blocks (except the exceptions) instead of from activation (#11739). |
| 24.0 | Taproot rules applied to all historical blocks except block 692261 (#23536). |
| 26.1 | Blocks from peers checked for mutation (`IsBlockMutated`) before they are processed (#29412). |
| 27.0 | Network-adjusted time removed; the two-hour future limit uses the local clock (#28956). |
| 28.0 | Testnet4 with BIP94 (timewarp fix, difficulty from the first block of a period) (#29775). |
| 32.1 | `taproot` removed from `getdeploymentinfo`, with no effect on validation (#26201). |

Two changes cannot be dated from the v32.1 source tree, whose release notes do not mention them: the removal of checkpoints (v32.1 has none) and the switch of the script error for bad numbers to `SCRIPTNUM` (v32.1 reports it).

## C.5 Proposals that are not consensus

Bitcoin Core v32.1 contains code for some proposals that are **not** consensus rules, and implementations must not enforce them when validating blocks:

- BIP54 ("consensus cleanup"): v32.1 applies its 2,500 legacy sigop limit to transactions only as relay policy, and its timestamp and coinbase rules only when building block templates.
- The 64-byte transaction check exists only to detect mutated blocks from peers (chapter 11 section 11.11); 64-byte transactions are valid in blocks.
- Pay-to-anchor outputs are standard for relay since 28.0, but consensus treats them like any unknown witness program: anyone can spend them.
