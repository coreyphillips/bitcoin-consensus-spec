//! `--known-failures FILE`: checks an implementation is known to fail.
//!
//! Each line that is not blank and does not start with `#` is `<suite> <check>`. The check is the
//! name the runner prints for a failure (`FAIL     [suite] <location>: ...`): the location up to its
//! first `:` or `(`, where the row text or a comment starts. An entry equals one name and waives
//! one failure: `row 15` names `row 15 (message of size 0 ...)`, and `tx-invalid row 7` names none
//! of that row's failures, each of which is named with its input and flags. An entry that waives
//! no failure, in a suite that ran, fails the run, so the list cannot outlive the failures it
//! describes or stand for several of them.
//!
//! The corpus suite names a level 0 failure by its check (`<file> check <n>`) and the replay
//! errors of a file, which fail that file once, as `<file> errors from event <n>`: `<n>` is the
//! event whose replay recorded the first error, so an earlier error does not pass as known.
//! `<file> errors` names them wherever they start.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Debug)]
struct Entry {
    suite: String,
    location: String,
    line: usize,
    used: bool,
    /// A failure whose name starts with this entry and a space, which the entry does not name.
    hint: Option<String>,
}

#[derive(Debug)]
pub struct Known {
    path: PathBuf,
    entries: Vec<Entry>,
}

/// An entry that named no failure.
pub struct Stale {
    pub suite: String,
    pub location: String,
    pub line: usize,
    /// The name of a failure the entry is the start of, which it was probably meant to name.
    pub hint: Option<String>,
}

/// The name of a failure location: the text before its first `:` or `(`. A script suite puts the
/// row text after `: `, and other suites a comment in parentheses, which may itself hold a colon
/// (BIP340's `sig[0:32] is equal to field size`).
pub fn check_name(location: &str) -> &str {
    let end = location.find([':', '(']).unwrap_or(location.len());
    location[..end].trim_end()
}

impl Known {
    pub fn parse(path: &Path, text: &str, suites: &[&str]) -> Result<Known, String> {
        let mut entries: Vec<Entry> = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = format!("{}:{}", path.display(), i + 1);
            let (suite, location) = line
                .split_once(char::is_whitespace)
                .map(|(s, l)| (s, l.trim()))
                .ok_or_else(|| format!("{at}: expected \"<suite> <location>\""))?;
            if !suites.contains(&suite) {
                return Err(format!("{at}: unknown suite {suite}"));
            }
            if check_name(location) != location {
                return Err(format!(
                    "{at}: name the check by what FAIL prints before the first \":\" or \"(\" (\"{}\")",
                    check_name(location)
                ));
            }
            if let Some(e) = entries
                .iter()
                .find(|e| e.suite == suite && e.location == location)
            {
                return Err(format!("{at}: repeats line {}", e.line));
            }
            entries.push(Entry {
                suite: suite.to_string(),
                location: location.to_string(),
                line: i + 1,
                used: false,
                hint: None,
            });
        }
        Ok(Known {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// True when an unused entry names this failure; the entry then waives no other. A check
    /// fails at most once per run, so a second failure under the same name is not one the list
    /// describes.
    pub fn take(&mut self, suite: &str, location: &str) -> bool {
        let name = check_name(location);
        let mut unused = self
            .entries
            .iter_mut()
            .filter(|e| e.suite == suite && !e.used);
        if let Some(e) = unused.find(|e| e.location == name) {
            e.used = true;
            return true;
        }
        for e in self
            .entries
            .iter_mut()
            .filter(|e| e.suite == suite && !e.used && e.hint.is_none())
        {
            if name
                .strip_prefix(e.location.as_str())
                .is_some_and(|rest| rest.starts_with(' '))
            {
                e.hint = Some(name.to_string());
            }
        }
        false
    }

    /// Entries of the suites in `ran` that named no failure.
    pub fn stale(&self, ran: &[&str]) -> Vec<Stale> {
        self.entries
            .iter()
            .filter(|e| !e.used && ran.contains(&e.suite.as_str()))
            .map(|e| Stale {
                suite: e.suite.clone(),
                location: e.location.clone(),
                line: e.line,
                hint: e.hint.clone(),
            })
            .collect()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

static KNOWN: OnceLock<Mutex<Known>> = OnceLock::new();

/// Reads the list for this run. Called at most once, before any suite runs.
pub fn load(path: &Path, suites: &[&str]) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let known = Known::parse(path, &text, suites)?;
    KNOWN
        .set(Mutex::new(known))
        .map_err(|_| "--known-failures given twice".to_string())
}

/// True when the run's list names this failure. False without `--known-failures`.
pub fn take(suite: &str, location: &str) -> bool {
    KNOWN
        .get()
        .is_some_and(|k| k.lock().unwrap().take(suite, location))
}

/// The list's path and its stale entries, or `None` without `--known-failures`.
pub fn stale(ran: &[&str]) -> Option<(PathBuf, Vec<Stale>)> {
    KNOWN.get().map(|k| {
        let k = k.lock().unwrap();
        (k.path().to_path_buf(), k.stale(ran))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUITES: &[&str] = &["bip340", "corpus", "interop", "tx-invalid"];

    fn known(text: &str) -> Result<Known, String> {
        Known::parse(Path::new("k.txt"), text, SUITES)
    }

    // The row text of tx_invalid.json row 7, as the runner prints it.
    const ROW_7: &str = "Use BADTX for verifyFlags if it is expected to fail CheckTransaction() \
                         Objects that are only a single string (like this one) are ignored";

    #[test]
    fn an_entry_names_one_check_by_its_whole_name() {
        let mut k = known(
            "# messages that are not 32 bytes\n\
             bip340 row 15\n\
             bip340 row 6\n\
             \n\
             corpus feature_block.node0 check 88\n\
             interop chain feature_spec_pitfalls.node2\n\
             tx-invalid row 7 input 0 flags P2SH\n\
             tx-invalid row 7 tx_check\n",
        )
        .unwrap();
        assert!(k.take("bip340", "row 15 (message of size 0 (added 2022-12))"));
        assert!(!k.take("bip340", "row 150 (another row)"));
        assert!(!k.take("bip340", "row 1"));
        assert!(k.take(
            "bip340",
            "row 6 (sig[0:32] is not an X coordinate on the curve)"
        ));
        assert!(!k.take("corpus", "row 15 (message of size 0 (added 2022-12))"));
        assert!(k.take(
            "corpus",
            "feature_block.node0 check 88 (event 352, line 354, send_blocks_and_test)"
        ));
        assert!(!k.take("corpus", "feature_block.node0 check 8 (event 1, line 3)"));
        assert!(k.take("interop", "chain feature_spec_pitfalls.node2"));
        assert!(!k.take("interop", "chain feature_spec_pitfalls.node20"));
        assert!(k.take("tx-invalid", &format!("row 7 input 0 flags P2SH: {ROW_7}")));
        assert!(!k.take(
            "tx-invalid",
            &format!("row 7 input 0 flags P2SH,WITNESS: {ROW_7}")
        ));
        assert!(!k.take("tx-invalid", &format!("row 7 input 0 flags NONE: {ROW_7}")));
        assert!(k.take("tx-invalid", &format!("row 7 tx_check: {ROW_7}")));
        assert!(k.stale(SUITES).is_empty());
    }

    #[test]
    fn an_entry_waives_one_failure() {
        let mut k = known("tx-invalid row 7 input 0 flags P2SH\n").unwrap();
        let loc = format!("row 7 input 0 flags P2SH: {ROW_7}");
        assert!(k.take("tx-invalid", &loc));
        assert!(!k.take("tx-invalid", &loc));
    }

    #[test]
    fn the_start_of_a_name_names_nothing_and_points_at_a_name_that_failed() {
        let mut k = known("tx-invalid row 7\ntx-invalid row\nbip340 row\n").unwrap();
        for flags in ["NONE", "P2SH", "P2SH,WITNESS"] {
            assert!(!k.take(
                "tx-invalid",
                &format!("row 7 input 0 flags {flags}: {ROW_7}")
            ));
        }
        assert!(!k.take("bip340", "row 15 (message of size 0 (added 2022-12))"));
        let stale = k.stale(SUITES);
        let hints: Vec<_> = stale.iter().map(|s| (s.line, s.hint.as_deref())).collect();
        assert_eq!(
            hints,
            [
                (1, Some("row 7 input 0 flags NONE")),
                (2, Some("row 7 input 0 flags NONE")),
                (3, Some("row 15")),
            ]
        );
    }

    #[test]
    fn an_unused_entry_is_stale_only_when_its_suite_ran() {
        let mut k = known("bip340 row 15\ncorpus mining_basic.node0 errors\n").unwrap();
        assert!(k.take("bip340", "row 15 (x)"));
        let stale = k.stale(SUITES);
        assert_eq!(stale.len(), 1);
        assert_eq!(
            (
                stale[0].suite.as_str(),
                stale[0].location.as_str(),
                stale[0].line
            ),
            ("corpus", "mining_basic.node0 errors", 2)
        );
        assert!(k.stale(&["bip340", "interop"]).is_empty());
    }

    #[test]
    fn a_malformed_list_is_refused() {
        assert!(known("bip340\n").unwrap_err().contains("k.txt:1"));
        assert!(known("nosuch row 1\n")
            .unwrap_err()
            .contains("unknown suite nosuch"));
        assert!(known("bip340 row 15\nbip340  row 15 \n")
            .unwrap_err()
            .contains("k.txt:2: repeats line 1"));
        // What FAIL prints after the name can never be part of one.
        assert!(known("bip340 row 15 (message of size 0)\n")
            .unwrap_err()
            .contains("k.txt:1: name the check by what FAIL prints before the first"));
        assert!(
            known(&format!("tx-invalid row 7 input 0 flags P2SH: {ROW_7}\n"))
                .unwrap_err()
                .contains("(\"row 7 input 0 flags P2SH\")")
        );
    }
}
