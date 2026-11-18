# Custom vectors

Targeted cases written for this project, each with the response Bitcoin Core v32.1's own code gives (computed with `conformance/oracle-core`). They cover rules that Bitcoin Core's test vectors do not reach, found by mutation testing: a deliberately broken copy of the reference passed every other suite. The last twelve cases come from bugs found in other published consensus implementations (Appendix A items 75, 76 and 79, and item 17 in tapscript): an ECDSA R or S above the group order forged to verify if reduced, R or S over 32 bytes or equal to the order under `DERSIG`, P2SH redeem scripts of 520 and 521 bytes, and the push limit in an unexecuted tapscript branch, both in a bare leaf and in a signed `<key> OP_CHECKSIG` leaf (the shape a published fast path recognizes).

`script-versions.jsonl` (from `generate_script_versions.py`) covers interpreter rules inside witness version 0 scripts, P2SH-wrapped witness programs and tapscripts, and legacy `FindAndDelete`. The other suites have almost no case where a rule is exercised inside one script version, so a rule switched off for that version alone passed them: the opcode, push and number size limits, strict DER, `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` in witness version 0 or tapscript, the commitment of an unknown tapleaf version (without it, every taproot output is spendable by anyone), and the P2SH-wrapped forms of the witness program rules. It also covers rules that only the block corpus reached before: the 10,000-byte witness script limit, witness scripts over 520 bytes (allowed), a lone key path signature that starts with 0x50 (not an annex), the disable bit of the input's sequence in `OP_CHECKSEQUENCEVERIFY`, taproot hash type 0x80, a control block of 129 nodes, `NULLDUMMY` in witness version 0, and the edges of every `OP_SUCCESS` range.

Format: JSON lines, one case per line, `{"name": ..., "request": <a PROTOCOL.md request without id>, "expect": <response fields that must match>}`. `valid` is scored at level 1; `script_error` and `reason` at level 2.

Regenerate with:

```sh
python3 conformance/vectors/custom/generate.py <oracle-core-harness> conformance/vectors/custom/edge-cases.jsonl
python3 conformance/vectors/custom/generate_script_versions.py <oracle-core-harness> conformance/vectors/custom/script-versions.jsonl
```
