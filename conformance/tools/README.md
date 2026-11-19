# Tools

`differential.py` sends the same random requests to two harnesses, counts every answer that differs and prints the first ten in each domain (`--show N` prints more). It stands in for the differential tools of the independent reviews in `RESULTS.md` section 2, which were written for those reviews and not kept. It reproduces their method for requests, not their figures.

| Domain | Requests | Chapters |
|---|---|---|
| `script` | `script_verify`: random scripts (bare and P2WSH) under random flags, and the committed custom vectors with their flags, transaction, scripts or amount changed | 02 to 07 |
| `tx` | `tx_check`: random transactions (empty, duplicate inputs, coinbase-shaped, out-of-range values) and the custom vectors' transactions with bytes changed | 08 |
| `pow` | `pow_compact`, `pow_check` and `pow_next_work` on all five networks: random bits, hashes next to the target, chains across and between retargets | 09 |
| `signet` | `signet_check`: the committed signet blocks with a bit flipped, under another or a changed challenge | 13 |

```sh
cargo build --release -p bitcoin-consensus-spec --bin reference-harness
BITCOIN_CORE_SRC=<Core v32.1 checkout> cargo build --release --manifest-path conformance/oracle-core/Cargo.toml
python3 conformance/tools/differential.py --cases 20000 --seed 1 \
  --a target/release/reference-harness --b conformance/oracle-core/target/release/oracle-core-harness
```

The same seed gives the same requests. A request both harnesses answer with `bad_request` (a changed transaction whose input count no longer matches `spent_outputs`, a block that no longer decodes) is counted as malformed and not compared. The exit status is 1 if any answer differs, a domain compares nothing, or a harness fails (`unsupported_op`, `internal`, a missing result field, a nonzero exit status). Any harness can be the `--a` side, so a candidate implementation can be checked against the oracle the same way.

The weekly `core` workflow runs 20,000 requests per domain with a new seed each time, printed in its log.

## Multi-branch scenarios

`multibranch.py` stands in for the reviews' 500 random multi-branch scenarios against a v32.1 node (chapters 10 to 12 and 15). Each scenario resets a regtest chain, mines a trunk past coinbase maturity, then grows random branches from it with the chain operations of PROTOCOL.md section 4:

- headers sent before their blocks (one `headers` message, or one header per request by `rpc`), and headers whose blocks never come;
- blocks sent in order, shuffled, reversed, unrequested or by `rpc`, children before their parents, and duplicates;
- transactions that spend outputs of the trunk and of their own branch, and invalid blocks that spend outputs created on another branch, spend twice, spend an immature coinbase, spend more than their inputs, claim too much in the coinbase, break BIP34, carry a wrong witness, fail proof of work, are dated at the median time past, or spend an output before the transaction that creates it;
- blocks dated exactly two hours after `now`, and blocks dated more than two hours after it, sent again once the clock has moved on;
- mutated copies of blocks (a duplicated last transaction, a transaction changed under the merkle root, a witness changed under the commitment), sent before or after the real block;
- invalidations of a reported chain tip or one of its recent ancestors.

After every chain operation past the trunk both harnesses are asked for `chain_tip`, `chain_tips` and `utxo_hash`, and the answers must be identical (the trunk is compared once, at its end). The first difference ends the scenario and prints the seed, the scenario, the step and both chain states. Per-request results are diagnostics (PROTOCOL.md section 4.9) and are not compared.

```sh
cargo build --release -p bitcoin-consensus-spec --bin reference-harness
BCS_BITCOIND=<v32.1 bitcoind> python3 conformance/tools/multibranch.py --scenarios 500 --seed 1 \
  --a target/release/reference-harness --b "python3 $PWD/conformance/recorder/core_chain_harness.py"
```

The same seed gives the same scenarios, and `--seed S --only I` runs scenario I alone; `--log FILE` writes every chain operation with both answers. Invalidations pick their block from the chain tips both harnesses reported, so a scenario repeats exactly up to its first difference. The exit status is 1 if any scenario differs or a harness fails. A scenario takes about three seconds against bitcoind.

The weekly `core` workflow runs 100 scenarios with a new seed each time, printed in its log.
