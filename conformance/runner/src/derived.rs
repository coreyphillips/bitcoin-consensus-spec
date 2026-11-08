//! Derived vector files (`conformance/vectors/derived/*.json`).
//!
//! A derived file records, for every script verification query built from one source vector file,
//! Bitcoin Core's verdict under each of the 64 valid combinations of the seven consensus flags.
//! Tx files also record Core's `tx_check` verdict per row. The files are written by
//! `bcs-conformance derive` from the answers of `oracle-core-harness`.

use crate::flags;
use crate::hex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

pub const FORMAT: &str = "bcs-derived-script-results/1";

/// Result characters: the character at position i of the results string is the result under
/// `flag_combinations[i]`, and its position in this alphabet indexes `errors`.
pub const ALPHABET: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Clone, Debug)]
pub struct ScriptEntry {
    pub digest: String,
    /// One error identifier per flag combination; `OK` means valid.
    pub results: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TxCheckEntry {
    pub digest: String,
    pub valid: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct DerivedFile {
    pub suite: String,
    pub source: String,
    pub source_sha256: String,
    pub provenance: Value,
    scripts: Vec<(String, ScriptEntry)>,
    script_index: HashMap<String, usize>,
    tx_checks: Vec<(String, TxCheckEntry)>,
    tx_check_index: HashMap<String, usize>,
    pub excluded: Vec<(String, String)>,
}

/// One JSON object on one line, with its fields in the given order.
fn entry_line(fields: &[(&str, Value)]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}:{v}", json!(k)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(hex::encode(&Sha256::digest(&data)))
}

impl DerivedFile {
    pub fn new(suite: &str, source: &str, source_sha256: &str, provenance: Value) -> Self {
        DerivedFile {
            suite: suite.into(),
            source: source.into(),
            source_sha256: source_sha256.into(),
            provenance,
            ..Default::default()
        }
    }

    pub fn add_script(&mut self, id: String, entry: ScriptEntry) {
        self.script_index.insert(id.clone(), self.scripts.len());
        self.scripts.push((id, entry));
    }

    pub fn add_tx_check(&mut self, id: String, entry: TxCheckEntry) {
        self.tx_check_index.insert(id.clone(), self.tx_checks.len());
        self.tx_checks.push((id, entry));
    }

    pub fn script(&self, id: &str) -> Option<&ScriptEntry> {
        self.script_index.get(id).map(|&i| &self.scripts[i].1)
    }

    pub fn tx_check(&self, id: &str) -> Option<&TxCheckEntry> {
        self.tx_check_index.get(id).map(|&i| &self.tx_checks[i].1)
    }

    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Serializes the file: a readable header, then one entry per line.
    pub fn to_text(&self) -> Result<String, String> {
        let combos = flags::consensus_combinations();
        let mut errors: BTreeSet<&str> = BTreeSet::new();
        for (_, e) in &self.scripts {
            for r in &e.results {
                if r != "OK" {
                    errors.insert(r);
                }
            }
        }
        let mut table: Vec<&str> = vec!["OK"];
        table.extend(errors.iter());
        if table.len() > ALPHABET.len() {
            return Err(format!(
                "too many distinct errors ({}) for the results alphabet",
                table.len()
            ));
        }
        let index: HashMap<&str, usize> = table.iter().enumerate().map(|(i, e)| (*e, i)).collect();

        let combos_json: Vec<Value> = combos.iter().map(|&c| json!(flags::names(c))).collect();
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"format\": {},\n", json!(FORMAT)));
        out.push_str(&format!("  \"suite\": {},\n", json!(self.suite)));
        out.push_str(&format!("  \"source\": {},\n", json!(self.source)));
        out.push_str(&format!(
            "  \"source_sha256\": {},\n",
            json!(self.source_sha256)
        ));
        let prov = serde_json::to_string_pretty(&self.provenance).map_err(|e| e.to_string())?;
        out.push_str(&format!(
            "  \"provenance\": {},\n",
            prov.replace('\n', "\n  ")
        ));
        out.push_str(&format!(
            "  \"results_encoding\": {},\n",
            json!("Each results string has one character per entry of flag_combinations, in that order. \
                   The character's position in 0-9a-zA-Z indexes errors. OK means the script is valid \
                   under that combination; any other identifier is Core's script error.")
        ));
        out.push_str(&format!(
            "  \"flag_combinations\": {},\n",
            Value::Array(combos_json)
        ));
        out.push_str(&format!("  \"errors\": {},\n", json!(table)));
        out.push_str("  \"tx_checks\": [");
        for (i, (id, e)) in self.tx_checks.iter().enumerate() {
            out.push_str(if i == 0 { "\n    " } else { ",\n    " });
            let mut fields = vec![
                ("id", json!(id)),
                ("digest", json!(e.digest)),
                ("valid", json!(e.valid)),
            ];
            if !e.valid {
                fields.push(("reason", json!(e.reason)));
            }
            out.push_str(&entry_line(&fields));
        }
        out.push_str(if self.tx_checks.is_empty() {
            "],\n"
        } else {
            "\n  ],\n"
        });
        out.push_str("  \"scripts\": [");
        for (i, (id, e)) in self.scripts.iter().enumerate() {
            if e.results.len() != combos.len() {
                return Err(format!("entry {id} has {} results", e.results.len()));
            }
            let results: String = e
                .results
                .iter()
                .map(|r| ALPHABET[index[r.as_str()]] as char)
                .collect();
            out.push_str(if i == 0 { "\n    " } else { ",\n    " });
            out.push_str(&entry_line(&[
                ("id", json!(id)),
                ("digest", json!(e.digest)),
                ("results", json!(results)),
            ]));
        }
        out.push_str(if self.scripts.is_empty() {
            "],\n"
        } else {
            "\n  ],\n"
        });
        out.push_str("  \"excluded\": [");
        for (i, (id, reason)) in self.excluded.iter().enumerate() {
            out.push_str(if i == 0 { "\n    " } else { ",\n    " });
            out.push_str(&entry_line(&[("id", json!(id)), ("reason", json!(reason))]));
        }
        out.push_str(if self.excluded.is_empty() {
            "]\n"
        } else {
            "\n  ]\n"
        });
        out.push_str("}\n");
        Ok(out)
    }

    pub fn load(path: &Path) -> Result<DerivedFile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let bad = |what: &str| format!("{}: {what}", path.display());
        if v["format"] != json!(FORMAT) {
            return Err(bad(&format!(
                "unknown format {}, expected {FORMAT}",
                v["format"]
            )));
        }
        let combos = flags::consensus_combinations();
        let file_combos = v["flag_combinations"]
            .as_array()
            .ok_or_else(|| bad("no flag_combinations"))?;
        let expected: Vec<Value> = combos.iter().map(|&c| json!(flags::names(c))).collect();
        if *file_combos != expected {
            return Err(bad(
                "flag_combinations differ from the runner's 64 combinations",
            ));
        }
        let errors: Vec<String> = v["errors"]
            .as_array()
            .ok_or_else(|| bad("no errors table"))?
            .iter()
            .map(|e| {
                e.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| bad("non-string error"))
            })
            .collect::<Result<_, _>>()?;
        let mut file = DerivedFile::new(
            v["suite"].as_str().unwrap_or_default(),
            v["source"].as_str().unwrap_or_default(),
            v["source_sha256"].as_str().unwrap_or_default(),
            v["provenance"].clone(),
        );
        let str_field = |e: &Value, k: &str| -> Result<String, String> {
            e[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| bad(&format!("entry without {k}")))
        };
        for e in v["tx_checks"]
            .as_array()
            .ok_or_else(|| bad("no tx_checks"))?
        {
            let valid = e["valid"]
                .as_bool()
                .ok_or_else(|| bad("tx_check without valid"))?;
            file.add_tx_check(
                str_field(e, "id")?,
                TxCheckEntry {
                    digest: str_field(e, "digest")?,
                    valid,
                    reason: e["reason"].as_str().unwrap_or_default().to_string(),
                },
            );
        }
        for e in v["scripts"].as_array().ok_or_else(|| bad("no scripts"))? {
            let id = str_field(e, "id")?;
            let encoded = str_field(e, "results")?;
            if encoded.len() != combos.len() {
                return Err(bad(&format!(
                    "entry {id}: results must have {} characters",
                    combos.len()
                )));
            }
            let results = encoded
                .bytes()
                .map(|c| {
                    ALPHABET
                        .iter()
                        .position(|&a| a == c)
                        .and_then(|i| errors.get(i).cloned())
                        .ok_or_else(|| bad(&format!("entry {id}: bad result character")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            file.add_script(
                id,
                ScriptEntry {
                    digest: str_field(e, "digest")?,
                    results,
                },
            );
        }
        for e in v["excluded"]
            .as_array()
            .ok_or_else(|| bad("no excluded list"))?
        {
            file.excluded
                .push((str_field(e, "id")?, str_field(e, "reason")?));
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip() {
        let combos = flags::consensus_combinations();
        let mut f = DerivedFile::new(
            "tx-invalid",
            "core/tx_invalid.json",
            "00",
            json!({"core_commit": "x"}),
        );
        let mut results = vec!["OK".to_string(); combos.len()];
        results[5] = "EVAL_FALSE".into();
        results[63] = "SIG_DER".into();
        f.add_script(
            "3/0".into(),
            ScriptEntry {
                digest: "0011223344556677".into(),
                results: results.clone(),
            },
        );
        f.add_tx_check(
            "3".into(),
            TxCheckEntry {
                digest: "8899aabbccddeeff".into(),
                valid: false,
                reason: "bad-txns-vout-empty".into(),
            },
        );
        f.excluded.push(("4/1".into(), "rule".into()));
        let path =
            std::env::temp_dir().join(format!("bcs-derived-test-{}.json", std::process::id()));
        std::fs::write(&path, f.to_text().unwrap()).unwrap();
        let g = DerivedFile::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(g.script("3/0").unwrap().results, results);
        assert_eq!(g.script("3/0").unwrap().digest, "0011223344556677");
        let t = g.tx_check("3").unwrap();
        assert!(!t.valid);
        assert_eq!(t.reason, "bad-txns-vout-empty");
        assert_eq!(g.excluded, vec![("4/1".to_string(), "rule".to_string())]);
        assert_eq!(g.source_sha256, "00");
    }
}
