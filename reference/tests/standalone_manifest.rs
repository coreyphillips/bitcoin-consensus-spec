//! The README tells readers without registry access to build a copy of reference/ and spec/ outside
//! the workspace. That copy has no workspace root, so its manifest must not inherit from one.

#[test]
fn the_manifest_inherits_nothing_from_the_workspace() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let inherited: Vec<&str> =
        manifest.lines().filter(|line| !line.trim_start().starts_with('#') && line.contains("workspace")).collect();
    assert!(inherited.is_empty(), "reference/Cargo.toml inherits from the workspace: {inherited:?}");
}
