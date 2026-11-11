//! `--known-failures FILE`: checks an implementation is known to fail.
//!
//! Each line that is not blank and does not start with `#` is `<suite> <location>`. The location
//! is the one the runner prints for a failure (`FAIL     [suite] <location>: ...`), or its start up
//! to a space: `row 15` names `row 15 (message of size 0 ...)` but not `row 150 ...`. A failure an
//! entry names is counted as known instead of failed. An entry that names no failure, in a suite
//! that ran, fails the run, so the list cannot outlive the failures it describes.
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
    hits: u64,
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
                hits: 0,
            });
        }
        Ok(Known {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// True when an entry names this failure; the entry is then marked as used.
    pub fn take(&mut self, suite: &str, location: &str) -> bool {
        let names = |e: &Entry| {
            e.suite == suite
                && location
                    .strip_prefix(e.location.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
        };
        match self.entries.iter_mut().find(|e| names(e)) {
            Some(e) => {
                e.hits += 1;
                true
            }
            None => false,
        }
    }

    /// Entries of the suites in `ran` that named no failure.
    pub fn stale(&self, ran: &[&str]) -> Vec<Stale> {
        self.entries
            .iter()
            .filter(|e| e.hits == 0 && ran.contains(&e.suite.as_str()))
            .map(|e| Stale {
                suite: e.suite.clone(),
                location: e.location.clone(),
                line: e.line,
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

    const SUITES: &[&str] = &["bip340", "corpus", "interop"];

    fn known(text: &str) -> Result<Known, String> {
        Known::parse(Path::new("k.txt"), text, SUITES)
    }

    #[test]
    fn an_entry_names_a_location_or_its_start_up_to_a_space() {
        let mut k = known(
            "# messages that are not 32 bytes\n\
             bip340 row 15\n\
             \n\
             corpus feature_block.node0 check 88\n\
             interop chain feature_spec_pitfalls.node2\n",
        )
        .unwrap();
        assert!(k.take("bip340", "row 15 (message of size 0 (added 2022-12))"));
        assert!(!k.take("bip340", "row 150 (another row)"));
        assert!(!k.take("bip340", "row 1"));
        assert!(!k.take("corpus", "row 15 (message of size 0 (added 2022-12))"));
        assert!(k.take(
            "corpus",
            "feature_block.node0 check 88 (event 352, line 354, send_blocks_and_test)"
        ));
        assert!(!k.take("corpus", "feature_block.node0 check 8 (event 1, line 3)"));
        assert!(k.take("interop", "chain feature_spec_pitfalls.node2"));
        assert!(!k.take("interop", "chain feature_spec_pitfalls.node20"));
        assert!(k.stale(SUITES).is_empty());
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
    }
}
