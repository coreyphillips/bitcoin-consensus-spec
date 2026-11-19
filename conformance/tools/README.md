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

Not reproduced: the 500 random multi-branch block scenarios against a v32.1 node (chapters 10 to 12 and 15). The repeatable evidence there is the recorded corpus, the `chainwork` scenario and the `peer-sync` suite.
