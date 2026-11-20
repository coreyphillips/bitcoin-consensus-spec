//! Builds the reference crate from the specification text.
//!
//! Every fenced code block whose info string is exactly `rust` in `spec/*.md` is normative. This
//! script copies those blocks, in document order, into one module per chapter. All chapter modules
//! are glob re-exported at the crate root and every module glob-imports the crate root, so code in
//! any chapter can name items from any other chapter, exactly as the prose does.
//!
//! Blocks marked `text` are not compiled. Any other fence fails the build, because a block opened
//! with `Rust`, `rs`, no info string, tildes or four backticks would otherwise drop out of the
//! crate unnoticed. A fence inside a block quote fails the build for the same reason.

use std::{env, fs, path::Path};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let spec_dir = Path::new(&manifest).join("..").join("spec");
    println!("cargo:rerun-if-changed={}", spec_dir.display());

    let version_file = spec_dir.join("VERSION");
    println!("cargo:rerun-if-changed={}", version_file.display());
    let version = fs::read_to_string(&version_file).expect("spec/VERSION");
    let version = version.trim();
    assert!(
        !version.is_empty() && !version.contains(char::is_whitespace),
        "spec/VERSION must hold one version, for example v32.1-3"
    );
    println!("cargo:rustc-env=BCS_SPEC_VERSION={version}");

    let mut chapters: Vec<_> = fs::read_dir(&spec_dir)
        .expect("spec directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |x| x == "md"))
        .collect();
    chapters.sort();

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let mut root = String::new();
    for path in chapters {
        println!("cargo:rerun-if-changed={}", path.display());
        let text = fs::read_to_string(&path).expect("read chapter");
        let file_name = path.file_name().unwrap().to_string_lossy().to_string();
        let code = extract(&text, &file_name).unwrap_or_else(|error| panic!("{error}"));
        if code.is_empty() {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let module = module_name(&stem);
        let out_file = Path::new(&out_dir).join(format!("{module}.rs"));
        let mut body = String::from("#[allow(unused_imports)]\nuse crate::*;\n\n");
        body.push_str(&code);
        fs::write(&out_file, body).expect("write module");
        root.push_str(&format!(
            "#[path = {:?}]\npub mod {module};\n#[allow(unused_imports)]\npub use {module}::*;\n\n",
            out_file.display().to_string()
        ));
    }
    fs::write(Path::new(&out_dir).join("chapters.rs"), root).expect("write chapters.rs");
}

/// Returns the normative Rust code of one chapter, with a comment pointing at the source line of
/// every block so compiler messages can be traced back to the document. Fails on any fence it
/// cannot classify as opening a `rust` block, opening a `text` block, or closing a block, and on
/// any fence that opens a block inside a block quote.
///
/// `tests/spec_fences.rs` includes this file to test this function.
pub(crate) fn extract(text: &str, file_name: &str) -> Result<String, String> {
    let mut out = String::new();
    // The line the open block started on, if one is open.
    let mut opened_at: Option<usize> = None;
    let mut normative = false;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let at = format!("spec/{file_name}:{number}");
        let trimmed = line.trim_start();
        if opened_at.is_none() {
            // A fence behind `>` markers still opens a code block, but the checks below would not
            // see it. Inside an open block the same line is only code.
            let mut unquoted = trimmed;
            while let Some(rest) = unquoted.strip_prefix('>') {
                unquoted = rest.trim_start();
            }
            let fence = unquoted.starts_with("```") || unquoted.starts_with("~~~");
            if fence && unquoted.len() < trimmed.len() {
                return Err(format!("{at}: code blocks must not be inside a block quote"));
            }
            if trimmed.starts_with("~~~") {
                return Err(format!("{at}: open code blocks with three backticks, not tildes"));
            }
        }
        let Some(rest) = trimmed.strip_prefix("```") else {
            if normative {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        };
        if rest.starts_with('`') {
            return Err(format!("{at}: code fences must be exactly three backticks"));
        }
        let info = rest.trim();
        match opened_at {
            None => {
                if info != "rust" && info != "text" {
                    return Err(format!(
                        "{at}: code block marked {info:?}; mark it \"rust\" (compiled) or \"text\" (not compiled)"
                    ));
                }
                opened_at = Some(number);
                normative = info == "rust";
                if normative {
                    out.push_str(&format!("// spec/{file_name}:{}\n", number + 1));
                }
            }
            // Markdown renders this line as part of the open block, so treating it as the close
            // would disagree with what readers see. It usually means a closing fence is missing.
            Some(opened) if !info.is_empty() => {
                return Err(format!(
                    "{at}: \"```{info}\" inside the code block opened at line {opened}; is that block missing its closing fence?"
                ));
            }
            Some(_) => {
                opened_at = None;
                if normative {
                    out.push('\n');
                }
                normative = false;
            }
        }
    }
    if let Some(opened) = opened_at {
        return Err(format!("spec/{file_name}:{opened}: code block is never closed"));
    }
    Ok(out)
}

/// `05-script-execution` becomes `ch05_script_execution`; `A-quirks` becomes `appendix_a_quirks`.
fn module_name(stem: &str) -> String {
    let cleaned: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect();
    if cleaned.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        format!("ch{cleaned}")
    } else {
        format!("appendix_{cleaned}")
    }
}
