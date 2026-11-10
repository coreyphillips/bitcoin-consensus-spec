# Custom vectors

Targeted cases written for this project, each with the response Bitcoin Core v32.1's own code gives (computed with `conformance/oracle-core`). They cover rules that Bitcoin Core's test vectors do not reach, found by mutation testing: a deliberately broken copy of the reference passed every other suite. The last eight cases come from bugs found in other published consensus implementations (Appendix A items 75, 76 and 79, and item 17 in tapscript): an ECDSA R or S above the group order forged to verify if reduced, oversized R and S under `DERSIG`, P2SH redeem scripts of 520 and 521 bytes, and the push limit in an unexecuted tapscript branch.

Format: JSON lines, one case per line, `{"name": ..., "request": <a PROTOCOL.md request without id>, "expect": <response fields that must match>}`. `valid` is scored at level 1; `script_error` and `reason` at level 2.

Regenerate with:

```sh
python3 conformance/vectors/custom/generate.py <oracle-core-harness> conformance/vectors/custom/edge-cases.jsonl
```
