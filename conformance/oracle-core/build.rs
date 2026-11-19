//! Compiles Bitcoin Core v32.1's consensus code from source.
//!
//! The Core source tree is located through the `BITCOIN_CORE_SRC` environment variable, which
//! must point at a git checkout of Bitcoin Core (the directory that contains `src/`). The build
//! refuses to continue unless that checkout is at the pinned commit and every file under `src/`
//! that the commit has holds that commit's content, so the oracle is always Core's own code.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Bitcoin Core v32.1 ("Merge bitcoin/bitcoin#36658: [32.x] Finalise 32.1").
const CORE_COMMIT: &str = "f0de87f040621468b956f01f526a43a010310501";
const CORE_VERSION: &str = "v32.1";

/// Core translation units linked into the oracle. `script/interpreter.cpp` is not listed: it is
/// compiled as part of `cpp/oracle.cpp` (see the comment at the top of that file).
const CORE_SOURCES: &[&str] = &[
    "script/script.cpp",
    "script/script_error.cpp",
    "primitives/transaction.cpp",
    "consensus/tx_check.cpp",
    "pubkey.cpp",
    "hash.cpp",
    "uint256.cpp",
    "crypto/ripemd160.cpp",
    "crypto/sha1.cpp",
    "crypto/sha256.cpp",
    "crypto/sha512.cpp",
    "crypto/hmac_sha512.cpp",
    "crypto/hex_base.cpp",
    "util/strencodings.cpp",
    "support/cleanse.cpp",
    "pow.cpp",
    "chain.cpp",
    "arith_uint256.cpp",
    "primitives/block.cpp",
    "consensus/merkle.cpp",
    "kernel/chainparams.cpp",
    "util/time.cpp",
    "signet.cpp",
];

fn fail(msg: &str) -> ! {
    // A panic in a build script prints the message to the user; keep it on one clear paragraph.
    panic!("\n\noracle-core: {msg}\n\n");
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Paths under `src/` whose working tree file is missing or differs from the pinned commit's.
///
/// `git status` trusts the index: a file marked `--assume-unchanged` or `--skip-worktree` looks
/// clean to it whatever it holds. Each file is hashed as it is on disk instead (`--no-filters`, so
/// no clean filter applies) and compared with the commit's tree, read with replace refs disabled.
fn differing_files(root: &Path) -> Result<Vec<String>, String> {
    let tree = git(
        root,
        &[
            "--no-replace-objects",
            "ls-tree",
            "-r",
            "-z",
            CORE_COMMIT,
            "--",
            "src",
        ],
    )?;
    let mut pinned = Vec::new();
    for entry in tree.split('\0').filter(|e| !e.is_empty()) {
        let (meta, path) = entry
            .split_once('\t')
            .ok_or_else(|| format!("unexpected git ls-tree line: {entry}"))?;
        let mut meta = meta.split(' ');
        let (mode, hash) = (meta.next(), meta.nth(1));
        match (mode, hash) {
            (Some("100644" | "100755"), Some(hash)) => pinned.push((path, hash)),
            _ => return Err(format!("{path} is not a regular file in {CORE_COMMIT}")),
        }
    }
    if pinned.is_empty() {
        return Err(format!("commit {CORE_COMMIT} has no files under src/"));
    }
    let mut differing = Vec::new();
    let present: Vec<_> = pinned
        .into_iter()
        .filter(|(path, _)| {
            let file = root.join(path).is_file();
            if !file {
                differing.push(format!("{path} (missing)"));
            }
            file
        })
        .collect();
    // In chunks, to stay well below the command line length limit.
    for chunk in present.chunks(500) {
        let mut args = vec!["hash-object", "--no-filters", "--"];
        args.extend(chunk.iter().map(|(path, _)| *path));
        let hashes = git(root, &args)?;
        let hashes: Vec<&str> = hashes.lines().collect();
        if hashes.len() != chunk.len() {
            return Err("git hash-object printed an unexpected number of hashes".into());
        }
        for ((path, expected), actual) in chunk.iter().zip(hashes) {
            if actual != *expected {
                differing.push(path.to_string());
            }
        }
    }
    Ok(differing)
}

fn first_line(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=BITCOIN_CORE_SRC");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cpp");

    let root = match env::var_os("BITCOIN_CORE_SRC") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => fail(&format!(
            "BITCOIN_CORE_SRC is not set. Point it at a git checkout of Bitcoin Core {CORE_VERSION} \
             (commit {CORE_COMMIT}), the directory that contains src/, for example:\n\n  \
             git clone --depth 1 --branch {CORE_VERSION} https://github.com/bitcoin/bitcoin.git bitcoin-core-{CORE_VERSION}\n  \
             BITCOIN_CORE_SRC=$PWD/bitcoin-core-{CORE_VERSION} cargo build --release"
        )),
    };
    let src = root.join("src");
    if !src.join("script/interpreter.cpp").is_file() {
        fail(&format!(
            "BITCOIN_CORE_SRC={} does not look like a Bitcoin Core checkout (src/script/interpreter.cpp is missing).",
            root.display()
        ));
    }
    let head = git(&root, &["rev-parse", "HEAD"]).unwrap_or_else(|e| {
        fail(&format!(
            "cannot read the commit of BITCOIN_CORE_SRC={} ({e}). It must be a git checkout of Bitcoin Core \
             {CORE_VERSION} (commit {CORE_COMMIT}); a shallow clone is enough.",
            root.display()
        ))
    });
    if head != CORE_COMMIT {
        fail(&format!(
            "BITCOIN_CORE_SRC={} is at commit {head}, but the oracle must be built from Bitcoin Core \
             {CORE_VERSION}, commit {CORE_COMMIT}. Run `git -C {} checkout {CORE_COMMIT}`.",
            root.display(),
            root.display()
        ));
    }
    let dirty = git(
        &root,
        &["status", "--porcelain", "--untracked-files=no", "--", "src"],
    )
    .unwrap_or_else(|e| {
        fail(&format!(
            "cannot check BITCOIN_CORE_SRC for local changes: {e}"
        ))
    });
    if !dirty.is_empty() {
        fail(&format!(
            "BITCOIN_CORE_SRC={} has local modifications under src/, so it is not Bitcoin Core {CORE_VERSION}:\n{dirty}",
            root.display()
        ));
    }
    let differing = differing_files(&root).unwrap_or_else(|e| {
        fail(&format!(
            "cannot compare BITCOIN_CORE_SRC={} with commit {CORE_COMMIT}: {e}",
            root.display()
        ))
    });
    if !differing.is_empty() {
        const SHOWN: usize = 20;
        let mut list = differing
            .iter()
            .take(SHOWN)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        if differing.len() > SHOWN {
            list += &format!("\n... and {} more", differing.len() - SHOWN);
        }
        fail(&format!(
            "BITCOIN_CORE_SRC={} has files under src/ whose content is not Bitcoin Core {CORE_VERSION}'s \
             (git status may not show them, for example when a file is marked --assume-unchanged):\n{list}",
            root.display()
        ));
    }
    // Rebuild when the checkout moves to another commit or a source file changes.
    if let Ok(git_dir) = git(&root, &["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
    }
    println!("cargo:rerun-if-changed={}", src.display());

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // C++ part: Core's consensus sources plus the C ABI bridge. DISABLE_OPTIMIZED_SHA256 selects
    // Core's portable SHA-256 code instead of the CPU-specific ones (identical results; those
    // live in separate translation units that would need per-CPU compiler flags).
    let mut cpp = cc::Build::new();
    cpp.cpp(true)
        .std("c++20")
        .include(&src)
        .include(src.join("secp256k1/include"))
        .define("DISABLE_OPTIMIZED_SHA256", None)
        .warnings(false)
        .file(manifest.join("cpp/oracle.cpp"))
        .file(manifest.join("cpp/check.cpp"))
        .file(manifest.join("cpp/pow.cpp"))
        .file(manifest.join("cpp/signet.cpp"))
        .file(manifest.join("cpp/log.cpp"));
    for file in CORE_SOURCES {
        cpp.file(src.join(file));
    }
    cpp.compile("bcs_oracle_core");

    // libsecp256k1 with the configuration Bitcoin Core v32.1 uses (cmake/secp256k1.cmake and
    // src/secp256k1/CMakeLists.txt defaults): ECDH off, recovery on, every other module on,
    // ECMULT_WINDOW_SIZE 15, ECMULT_GEN_KB 86 (COMB_BLOCKS 43, COMB_TEETH 6).
    let mut secp = cc::Build::new();
    secp.include(src.join("secp256k1/include"))
        .include(src.join("secp256k1/src"))
        .define("SECP256K1_NO_API_VISIBILITY_ATTRIBUTES", None)
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("COMB_BLOCKS", "43")
        .define("COMB_TEETH", "6")
        .define("ENABLE_MODULE_ELLSWIFT", "1")
        .define("ENABLE_MODULE_MUSIG", "1")
        .define("ENABLE_MODULE_SILENTPAYMENTS", "1")
        .define("ENABLE_MODULE_SCHNORRSIG", "1")
        .define("ENABLE_MODULE_EXTRAKEYS", "1")
        .define("ENABLE_MODULE_RECOVERY", "1")
        .warnings(false)
        .file(src.join("secp256k1/src/secp256k1.c"))
        .file(src.join("secp256k1/src/precomputed_ecmult.c"))
        .file(src.join("secp256k1/src/precomputed_ecmult_gen.c"));
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        secp.define("USE_ASM_X86_64", "1");
    }
    secp.compile("bcs_oracle_secp256k1");

    // Provenance reported by the `info` operation.
    let compiler = cpp.get_compiler();
    let compiler_version = first_line(&compiler.path().to_string_lossy(), &["--version"]);
    let rustc = first_line(
        &env::var("RUSTC").unwrap_or_else(|_| "rustc".into()),
        &["--version"],
    );
    let build = format!(
        "core {CORE_VERSION} {CORE_COMMIT}; target {}; profile {} (opt-level {}); c++: {compiler_version}; {rustc}",
        env::var("TARGET").unwrap_or_default(),
        env::var("PROFILE").unwrap_or_default(),
        env::var("OPT_LEVEL").unwrap_or_default(),
    );
    println!("cargo:rustc-env=ORACLE_CORE_COMMIT={CORE_COMMIT}");
    println!("cargo:rustc-env=ORACLE_CORE_VERSION={CORE_VERSION}");
    println!("cargo:rustc-env=ORACLE_BUILD={build}");
}
