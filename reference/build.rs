//! Builds the reference crate from the specification text.
//!
//! Every fenced code block whose info string is exactly `rust` in `spec/NN-*.md` is normative. This
//! script copies those blocks, in document order, into one module per chapter. All chapter modules
//! are glob re-exported at the crate root and every module glob-imports the crate root, so code in
//! any chapter can name items from any other chapter, exactly as the prose does.
//!
//! Blocks with any other info string (`text`, `rust,ignore`, ...) are not compiled.

use std::{env, fs, path::Path};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let spec_dir = Path::new(&manifest).join("..").join("spec");
    println!("cargo:rerun-if-changed={}", spec_dir.display());

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
        let code = extract(&text, &file_name);
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
/// every block so compiler messages can be traced back to the document.
fn extract(text: &str, file_name: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    let mut normative = false;
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if !in_block {
            if let Some(info) = trimmed.strip_prefix("```") {
                in_block = true;
                normative = info.trim() == "rust";
                if normative {
                    out.push_str(&format!("// spec/{}:{}\n", file_name, number + 2));
                }
            }
        } else if trimmed.starts_with("```") {
            in_block = false;
            if normative {
                out.push('\n');
            }
        } else if normative {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(!in_block, "unterminated code block in spec/{file_name}");
    out
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
