//! build.rs fails on a code fence it cannot classify, so a mistyped fence stops the build instead of
//! dropping a normative block from the crate.

#[allow(dead_code)]
#[path = "../build.rs"]
mod build;

fn extract(text: &str) -> Result<String, String> {
    build::extract(text, "99-test.md")
}

#[test]
fn rust_blocks_are_compiled_and_text_blocks_are_not() {
    let code = extract("prose\n```rust\nfn a() {}\n```\n\n```text\ndiagram\n```\n  ```rust\n  fn b() {}\n  ```\n").unwrap();
    assert_eq!(code, "// spec/99-test.md:3\nfn a() {}\n\n// spec/99-test.md:10\n  fn b() {}\n\n");
}

#[test]
fn a_mistyped_opening_fence_fails() {
    for opening in ["```Rust", "```rs", "```rust,ignore", "```", "````rust", "~~~rust", "```rust blocks are normative"] {
        let text = format!("prose\n{opening}\nfn a() {{}}\n```\n");
        match extract(&text) {
            Err(error) => assert!(error.starts_with("spec/99-test.md:2: "), "{opening}: {error}"),
            Ok(code) => panic!("{opening} was accepted and gave {code:?}"),
        }
    }
}

#[test]
fn a_fence_inside_a_block_quote_fails() {
    for opening in [
        "> ```rust",
        "> ```Rust",
        "> ```text",
        ">```rust",
        "> > ```rust",
        "  >   ```rust",
        "> ~~~rust",
        "- > ```rust",
        "1. > ```rust",
        "> * ```rust",
    ] {
        let text = format!("> prose\n{opening}\n> fn a() {{}}\n> ```\n");
        match extract(&text) {
            Err(error) => {
                assert!(error.starts_with("spec/99-test.md:2: "), "{opening}: {error}");
                assert!(error.contains("block quote"), "{opening}: {error}");
            }
            Ok(code) => panic!("{opening} was accepted and gave {code:?}"),
        }
    }
}

#[test]
fn indented_code_in_a_block_quote_is_not_a_fence() {
    assert_eq!(extract(">     ```rust\n>     fn a() {}\n>     ```\n").unwrap(), "");
}

#[test]
fn quote_markers_inside_a_block_are_code() {
    assert_eq!(extract("> prose\n```text\n> ```rust\n```\n").unwrap(), "");
    assert_eq!(extract("```rust\n> ```\n```\n").unwrap(), "// spec/99-test.md:2\n> ```\n\n");
}

#[test]
fn an_info_string_inside_a_block_fails() {
    let error = extract("```text\ndiagram\n```rust\nfn a() {}\n```\n").unwrap_err();
    assert!(error.starts_with("spec/99-test.md:3: "), "{error}");
    assert!(error.contains("opened at line 1"), "{error}");
}

#[test]
fn an_unclosed_block_fails() {
    let error = extract("prose\n```rust\nfn a() {}\n").unwrap_err();
    assert!(error.starts_with("spec/99-test.md:2: "), "{error}");
}
