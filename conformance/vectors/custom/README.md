# Custom vectors

Targeted cases written for this project, each with the response Bitcoin Core v32.1's own code gives (computed with `conformance/oracle-core`). They cover rules that Bitcoin Core's test vectors do not reach, found by mutation testing: a deliberately broken copy of the reference passed every other suite.

Format: JSON lines, one case per line, `{"name": ..., "request": <a PROTOCOL.md request without id>, "expect": <response fields that must match>}`. `valid` is scored at level 1; `script_error` and `reason` at level 2.

Regenerate with:

```sh
python3 conformance/vectors/custom/generate.py <oracle-core-harness> conformance/vectors/custom/edge-cases.jsonl
```
