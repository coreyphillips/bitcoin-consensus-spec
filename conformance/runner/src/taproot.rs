//! The taproot placeholders of script_tests.json.
//!
//! Core's `script_json_test` builds them with a `TaprootBuilder` holding one tapscript leaf at
//! depth 0 and the internal key of its test key `key0` (secret key 1):
//!
//! - `#CONTROLBLOCK#` becomes the leaf's control block: `0xc0 | parity` followed by the 32-byte
//!   internal key (no merkle path, since the tree is a single leaf);
//! - `0x51 0x20 #TAPROOTOUTPUT#` becomes `OP_1 <32-byte output key>`.
//!
//! The merkle root of a single-leaf tree is the leaf hash, and the output key is the internal key
//! tweaked by `TapTweak(internal_key || merkle_root)` (BIP341).

use crate::tx::write_compact_size;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// BIP340 tagged hash.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// BIP341 tapleaf hash.
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut len = Vec::new();
    write_compact_size(&mut len, script.len() as u64);
    tagged_hash("TapLeaf", &[&[leaf_version], &len, script])
}

/// The x-only public key of Core's test key `key0` (secret key 1).
pub fn key0_xonly() -> [u8; 32] {
    let secp = Secp256k1::signing_only();
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let sk = SecretKey::from_byte_array(secret).expect("1 is a valid secret key");
    PublicKey::from_secret_key(&secp, &sk)
        .x_only_public_key()
        .0
        .serialize()
}

/// Control block and output key for a tree made of one tapscript leaf.
pub fn single_leaf(internal: [u8; 32], script: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let secp = Secp256k1::verification_only();
    let internal_key =
        XOnlyPublicKey::from_byte_array(internal).map_err(|e| format!("internal key: {e}"))?;
    let merkle_root = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, script);
    let tweak = tagged_hash("TapTweak", &[&internal, &merkle_root]);
    let tweak = Scalar::from_be_bytes(tweak).map_err(|_| "tweak out of range".to_string())?;
    let (output, parity) = internal_key
        .add_tweak(&secp, &tweak)
        .map_err(|e| format!("tweak: {e}"))?;
    let mut control = vec![TAPSCRIPT_LEAF_VERSION | parity.to_u8()];
    control.extend_from_slice(&internal);
    Ok((control, output.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn core_tapleaf_vectors() {
        // src/test/script_tests.cpp, compute_tapleaf.
        assert_eq!(
            hex::encode_reversed(&tapleaf_hash(0xc0, b"foobar")),
            "edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"
        );
        assert_eq!(
            hex::encode_reversed(&tapleaf_hash(0xc2, b"foobar")),
            "8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"
        );
    }

    #[test]
    fn key0_is_generator() {
        assert_eq!(
            hex::encode(&key0_xonly()),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn bip341_single_leaf_vector() {
        // bip341_wallet_vectors.json, scriptPubKey[1]: one leaf at depth 0.
        let internal =
            hex::decode32("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27")
                .unwrap();
        let script =
            hex::decode("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac")
                .unwrap();
        let (control, output) = single_leaf(internal, &script).unwrap();
        assert_eq!(
            hex::encode(&control),
            "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"
        );
        assert_eq!(
            hex::encode(&output),
            "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"
        );
    }
}
