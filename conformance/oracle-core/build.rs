//! Compiles Bitcoin Core v32.1's consensus code from source.
//!
//! The Core source tree is located through the `BITCOIN_CORE_SRC` environment variable, which
//! must point at a git checkout of Bitcoin Core (the directory that contains `src/`). The build
//! refuses to continue unless that checkout is at the pinned commit and has no local
//! modifications under `src/`, so the oracle is always Core's own code.

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
        .file(manifest.join("cpp/check.cpp"));
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
