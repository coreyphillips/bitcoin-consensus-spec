# 12. Network parameters

Bitcoin Core supports five networks. They share every rule in this specification and differ only in the parameters below. Mainnet is the network that matters; the others exist for testing, and implementations SHOULD support them because the conformance suite uses regtest heavily and the test networks exercise rules (minimum-difficulty blocks, BIP94, signet block signatures) that mainnet does not.

## 12.1 Parameter set

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

/// Consensus parameters. Core: `Consensus::Params`, `src/consensus/params.h`.
#[derive(Clone, Debug)]
pub struct ConsensusParams {
    pub network: Network,
    pub genesis_hash: Hash256,
    pub subsidy_halving_interval: i32,
    /// Height from which BIP34 (height in coinbase) and the block version 2 floor apply.
    pub bip34_height: i32,
    /// Hash of the block at `bip34_height` on this network's chain, or zero (chapter 10, BIP30).
    pub bip34_hash: Hash256,
    /// BIP65 (CHECKLOCKTIMEVERIFY, version 4 floor).
    pub bip65_height: i32,
    /// BIP66 (strict DER, version 3 floor).
    pub bip66_height: i32,
    /// BIP68, BIP112, BIP113 (relative lock time, CHECKSEQUENCEVERIFY, median time past for lock times).
    pub csv_height: i32,
    /// BIP141, BIP143, BIP147 (segregated witness, NULLDUMMY).
    pub segwit_height: i32,
    pub pow_limit: U256,
    pub pow_target_timespan: i64,
    pub pow_target_spacing: i64,
    pub pow_allow_min_difficulty_blocks: bool,
    pub pow_no_retargeting: bool,
    pub enforce_bip94: bool,
    /// Blocks whose script flags differ from the default (chapter 10).
    pub script_flag_exceptions: Vec<(Hash256, ScriptFlags)>,
    /// Signet only: the block signing challenge (chapter 13).
    pub signet_challenge: Option<Vec<u8>>,
}

impl ConsensusParams {
    /// Core: `Consensus::Params::DifficultyAdjustmentInterval`.
    pub fn difficulty_adjustment_interval(&self) -> i64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

/// Everything a node needs to know about a network.
#[derive(Clone, Debug)]
pub struct NetworkParams {
    pub consensus: ConsensusParams,
    pub genesis: Block,
    /// The four bytes that start every peer-to-peer message (chapter 14).
    pub magic: [u8; 4],
    pub default_port: u16,
}
```

## 12.2 Values

| Parameter | main | testnet3 | testnet4 | signet | regtest |
|---|---|---|---|---|---|
| Subsidy halving interval | 210,000 | 210,000 | 210,000 | 210,000 | 150 |
| BIP34 height | 227,931 | 21,111 | 1 | 1 | 1 |
| BIP65 height | 388,381 | 581,885 | 1 | 1 | 1 |
| BIP66 height | 363,725 | 330,776 | 1 | 1 | 1 |
| CSV height | 419,328 | 770,112 | 1 | 1 | 1 |
| Segwit height | 481,824 | 834,624 | 1 | 1 | 0 |
| Target timespan | 2 weeks | 2 weeks | 2 weeks | 2 weeks | 1 day |
| Target spacing | 10 min | 10 min | 10 min | 10 min | 10 min |
| Adjustment interval | 2016 | 2016 | 2016 | 2016 | 144 |
| Minimum-difficulty blocks | no | yes | yes | no | yes |
| No retargeting | no | no | no | no | yes |
| BIP94 | no | no | yes | no | option |
| Message start | `f9beb4d9` | `0b110907` | `1c163f28` | derived | `fabfb5da` |
| Default port | 8333 | 18333 | 48333 | 38333 | 18444 |

Taproot (BIP341/342) has no activation height: its rules apply to every block except the script flag exceptions listed in chapter 10 section 10.6 (two blocks on mainnet, one on testnet3). There are no soft-fork deployments in progress in Bitcoin Core v32.1, so no version bits state machine (BIP9) is needed to validate any network.

Two more per-network values in Bitcoin Core are **not consensus** and are not part of `NetworkParams`. They are listed here because chapters 11 and 14 refer to them. Bitcoin Core updates both in most releases.

| Value (Core) | main | testnet3 | testnet4 | signet (default) | regtest |
|---|---|---|---|---|---|
| Minimum chain work (`nMinimumChainWork`) | `0x145ec036acc5ba740052af1a0` | `0x17f49f702147f10c0eb6` | `0xe346a558455ade8eca9` | `0x1090e9dc1520` | 0 |
| Assume-valid block (`defaultAssumeValid`) | 966,143: `00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3` | 5,128,859: `00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637` | 151,604: `0000000021df65b91665a342e26ceb05e54826ad7d8fcd40316230058fa3b865` | 321,295: `00000002a5e0ba0498f1e9f4591af0b66b63c654665efe65206fd0ae7bbaf923` | none |

The minimum chain work protects a node against peers that feed it long chains of cheap headers or blocks (chapter 11 section 11.6 step 4, chapter 14). The reference uses zero on every network, as Bitcoin Core does with `-minimumchainwork=0`; that is safe when the node connects only to peers it trusts. A node exposed to untrusted peers SHOULD use Bitcoin Core's value, and then also needs Bitcoin Core's low-work headers synchronization (chapter 14 section 14.3), because with a nonzero minimum every header message of an honest chain is below the threshold until the node has most of the chain. A custom signet uses zero. The assume-valid block is the optimization described in chapter 11 section 11.12. (Core: `consensus.nMinimumChainWork`, `consensus.defaultAssumeValid`, `src/kernel/chainparams.cpp`.)

## 12.3 Genesis blocks

Every genesis block has one transaction: version 1, lock time 0, one input with a null outpoint, sequence `0xffffffff` and a `script_sig` of `push_int(486604799) || push_data([4]) || push_data(message)`, and one output of 50 BTC. The genesis block is never validated: it is the root of the chain by definition, and its coinbase output is **not** added to the UTXO set, so it cannot be spent (chapter 10). Its outpoint is not reserved, though: the coinbase's `script_sig` starts with `push_int(486604799)`, so a byte-identical coinbase meets BIP34 at height 486,604,799 and passes BIP30 (there is no unspent output to overwrite), and its output, with the same outpoint, then enters the UTXO set like any other. The coinbase alone is not enough: the subsidy is 0 at that height, so its 50 BTC output needs a block that collects at least 50 BTC in fees, and because it has no witness commitment, none of that block's transactions may carry witness data. No rule treats the genesis transaction id specially. (Core: `CreateGenesisBlock`, `src/kernel/chainparams.cpp`.)

```rust
/// Core: `CreateGenesisBlock`.
pub fn create_genesis_block(message: &[u8], output_script: Vec<u8>, time: u32, nonce: u32, bits: u32, version: i32, reward: i64) -> Block {
    let mut script_sig = push_int(486604799);
    script_sig.extend_from_slice(&push_data(&[4]));
    script_sig.extend_from_slice(&push_data(message));
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn { prevout: OutPoint::null(), script_sig, sequence: 0xffff_ffff, witness: Vec::new() }],
        outputs: vec![TxOut { value: reward, script_pubkey: output_script }],
        lock_time: 0,
    };
    let merkle_root = coinbase.txid();
    Block {
        header: BlockHeader { version, prev_block: ZERO_HASH, merkle_root, time, bits, nonce },
        transactions: vec![coinbase],
    }
}

const SATOSHI_MESSAGE: &[u8] = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
const SATOSHI_PUBKEY: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";
const TESTNET4_MESSAGE: &[u8] = b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";

fn p2pk_script(pubkey: &[u8]) -> Vec<u8> {
    let mut script = push_data(pubkey);
    script.push(OP_CHECKSIG);
    script
}
```

## 12.4 Signet

A signet is a test network whose blocks must, in addition to proof of work, carry a valid signature for a *challenge* script (chapter 13). The default signet's challenge is a 1-of-2 multisig script; any other challenge defines a different signet with its own message start. The message start is the first four bytes of `sha256d(var_bytes(challenge))`. (Core: `SigNetParams`.)

```rust
/// The default signet challenge. Core: `SigNetParams`.
pub const DEFAULT_SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
```

## 12.5 Test overrides

For testing, Bitcoin Core lets the deployment heights of non-mainnet networks be overridden (`-testactivationheight=name@height` with `name` one of `bip34`, `dersig`, `cltv`, `csv`, `segwit`), and lets regtest enforce BIP94 (`-test=bip94`). Signet accepts a custom challenge (`-signetchallenge`). The conformance suite's recorded scenarios use these options, so implementations that want to pass the suite MUST support them for non-mainnet networks. (Core: `HandleDeploymentArgs`, `ReadTestNetArgs`, `ReadSigNetArgs`, `ReadRegTestArgs`, `src/chainparams.cpp`; mainnet refuses `-testactivationheight` in `AppInitParameterInteraction`, `src/init.cpp`.)

```rust
/// Test overrides. Core: `CChainParams::DeploymentOptions`, `RegTestOptions`, `SigNetOptions`.
#[derive(Clone, Debug, Default)]
pub struct NetworkOptions {
    /// `(name, height)` with name one of bip34, dersig, cltv, csv, segwit.
    pub activation_heights: Vec<(String, i32)>,
    /// Regtest only.
    pub enforce_bip94: bool,
    /// Signet only.
    pub signet_challenge: Option<Vec<u8>>,
}

fn hash_from_hex(display: &str) -> Hash256 {
    hash_from_display(display).expect("valid constant")
}

fn target_from_hex(text: &str) -> U256 {
    U256::from_be_bytes(&hex_decode(text).expect("valid constant"))
}

/// Builds the parameters of a network. Panics on an invalid override name or a mainnet override.
pub fn network_params(network: Network, options: &NetworkOptions) -> NetworkParams {
    let satoshi_script = p2pk_script(&hex_decode(SATOSHI_PUBKEY).unwrap());
    let main_limit = target_from_hex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let two_weeks = 14 * 24 * 60 * 60;
    let mut consensus = ConsensusParams {
        network,
        genesis_hash: ZERO_HASH,
        subsidy_halving_interval: 210_000,
        bip34_height: 1,
        bip34_hash: ZERO_HASH,
        bip65_height: 1,
        bip66_height: 1,
        csv_height: 1,
        segwit_height: 1,
        pow_limit: main_limit,
        pow_target_timespan: two_weeks,
        pow_target_spacing: 10 * 60,
        pow_allow_min_difficulty_blocks: false,
        pow_no_retargeting: false,
        enforce_bip94: false,
        script_flag_exceptions: Vec::new(),
        signet_challenge: None,
    };
    let (genesis, magic, default_port) = match network {
        Network::Main => {
            consensus.bip34_height = 227_931;
            consensus.bip34_hash = hash_from_hex("000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
            consensus.bip65_height = 388_381;
            consensus.bip66_height = 363_725;
            consensus.csv_height = 419_328;
            consensus.segwit_height = 481_824;
            consensus.script_flag_exceptions = vec![
                // BIP16 exception: block 170060.
                (hash_from_hex("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), 0),
                // Taproot exception: block 692261.
                (hash_from_hex("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), VERIFY_P2SH | VERIFY_WITNESS),
            ];
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN), [0xf9, 0xbe, 0xb4, 0xd9], 8333)
        }
        Network::Testnet3 => {
            consensus.bip34_height = 21_111;
            consensus.bip34_hash = hash_from_hex("0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
            consensus.bip65_height = 581_885;
            consensus.bip66_height = 330_776;
            consensus.csv_height = 770_112;
            consensus.segwit_height = 834_624;
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.script_flag_exceptions =
                vec![(hash_from_hex("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), 0)];
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN), [0x0b, 0x11, 0x09, 0x07], 18333)
        }
        Network::Testnet4 => {
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.enforce_bip94 = true;
            let script = p2pk_script(&[0u8; 33]);
            (create_genesis_block(TESTNET4_MESSAGE, script, 1714777860, 393743547, 0x1d00ffff, 1, 50 * COIN), [0x1c, 0x16, 0x3f, 0x28], 48333)
        }
        Network::Signet => {
            consensus.pow_limit = target_from_hex("00000377ae000000000000000000000000000000000000000000000000000000");
            let challenge = options.signet_challenge.clone().unwrap_or_else(|| hex_decode(DEFAULT_SIGNET_CHALLENGE).unwrap());
            let mut serialized = Vec::new();
            write_var_bytes(&mut serialized, &challenge);
            let digest = sha256d(&serialized);
            consensus.signet_challenge = Some(challenge);
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN), [digest[0], digest[1], digest[2], digest[3]], 38333)
        }
        Network::Regtest => {
            consensus.subsidy_halving_interval = 150;
            consensus.segwit_height = 0;
            consensus.pow_limit = target_from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            consensus.pow_target_timespan = 24 * 60 * 60;
            consensus.pow_allow_min_difficulty_blocks = true;
            consensus.pow_no_retargeting = true;
            consensus.enforce_bip94 = options.enforce_bip94;
            (create_genesis_block(SATOSHI_MESSAGE, satoshi_script, 1296688602, 2, 0x207fffff, 1, 50 * COIN), [0xfa, 0xbf, 0xb5, 0xda], 18444)
        }
    };
    if !options.activation_heights.is_empty() {
        assert!(network != Network::Main, "deployment overrides are not allowed on mainnet");
    }
    for (name, height) in &options.activation_heights {
        match name.as_str() {
            "bip34" => consensus.bip34_height = *height,
            "dersig" => consensus.bip66_height = *height,
            "cltv" => consensus.bip65_height = *height,
            "csv" => consensus.csv_height = *height,
            "segwit" => consensus.segwit_height = *height,
            other => panic!("unknown deployment {other}"),
        }
    }
    consensus.genesis_hash = genesis.hash();
    NetworkParams { consensus, genesis, magic, default_port }
}
```

## 12.6 Known-answer tests

```rust
#[cfg(test)]
mod network_parameter_tests {
    use super::*;

    #[test]
    fn genesis_hashes() {
        let expect = [
            (Network::Main, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
            (Network::Testnet3, "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"),
            (Network::Testnet4, "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"),
            (Network::Signet, "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
            (Network::Regtest, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        ];
        for (network, hash) in expect {
            let params = network_params(network, &NetworkOptions::default());
            assert_eq!(hash_to_display(&params.consensus.genesis_hash), hash, "{network:?}");
        }
        let main = network_params(Network::Main, &NetworkOptions::default());
        assert_eq!(hash_to_display(&main.genesis.header.merkle_root), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        let testnet4 = network_params(Network::Testnet4, &NetworkOptions::default());
        assert_eq!(hash_to_display(&testnet4.genesis.header.merkle_root), "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e");
        let signet = network_params(Network::Signet, &NetworkOptions::default());
        assert_eq!(hex_encode(&signet.magic), "0a03cf40");
    }
}
```
