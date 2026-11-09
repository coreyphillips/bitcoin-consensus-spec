# 11. Chain state and chain selection

Chapters 08 to 10 decide whether a block is valid given its ancestors. This chapter decides which chain a node follows, what it remembers about blocks it has seen, and how it moves between chains. Getting this wrong does not make a node accept an invalid block, but it can leave the node on a different chain from the rest of the network, or make it refuse forever a block it will need. Both have happened to independent implementations.

## 11.1 Rules

1. **Most work wins.** The active chain is the valid chain with the most cumulative work (chapter 09), not the longest chain.
2. **First seen wins ties.** Among chains with equal work, the one whose tip block became *linked* first is preferred. A block is linked when its data and the data of all its ancestors have been received; blocks receive a strictly increasing *sequence number* at that moment, and lower is better. When a block's arrival links several waiting descendants, they are numbered in breadth-first order from it, children in the order they arrived. A node never switches between equal-work chains on its own. Bitcoin Core does not store sequence numbers: after a restart, every block of its active chain shares the best number and every other linked block shares the next one, and remaining ties are broken by memory address (Core: `LoadChainTip`, `SEQ_ID_BEST_CHAIN_FROM_DISK`, `CBlockIndexWorkComparator`). The first-seen rule therefore holds within one run of a node; across a restart only the preference for the active chain survives.
3. **Validity is a property of the whole chain.** A block is part of a valid chain only if every ancestor is valid. When a block is found invalid, every descendant is invalid too, now and for any descendant learned later.
4. **Only commitments may be remembered.** A node may permanently record a block hash as invalid only for failures that are determined by the data the hash commits to (kind `Invalid` from the header, contextual body or connection checks). It MUST NOT record anything for `Mutated` or `Temporary` failures, and Bitcoin Core does not record failures of the context-free body checks (`check_block`) at all, because a body that fails them may not be the body the header commits to (for example a forged body exploiting the 64-byte transaction ambiguity of the merkle tree).
5. **Fail closed, everywhere.** If anything needed to validate a block is missing, the block is not valid (chapter 01).
6. **Equivalence of implementations.** Implementations may validate side branches eagerly or lazily, in parallel or in batches, and may persist state however they like. They MUST select the same active chain as the reference after every block they process (given the same blocks in the same order, with the same `requested` flags, within one run), and their UTXO set MUST equal the reference's (chapter 15 gives a fingerprint to compare).

The rest of this chapter specifies the reference algorithm, which follows Bitcoin Core's `ChainstateManager::ProcessNewBlock`, `AcceptBlockHeader`, `AcceptBlock`, `ReceivedBlockTransactions`, `ActivateBestChain` and `InvalidateBlock` (`src/validation.cpp`).

## 11.2 The block tree

Every header the node has accepted is an entry in the block tree, whether or not the block's data has arrived.

```rust
/// Core: `CBlockIndex`, `src/chain.h`.
#[derive(Clone, Debug)]
pub struct BlockEntry {
    pub hash: Hash256,
    pub header: BlockHeader,
    pub height: i32,
    pub parent: Option<Hash256>,
    pub chain_work: U256,
    /// Median time past of this block (chapter 09).
    pub median_time_past: i64,
    /// The block's data, once received and accepted.
    pub block: Option<Block>,
    /// Undo data, while the block is connected or after it has been.
    pub undo: Option<BlockUndo>,
    /// Sequence number assigned when the block became linked; 0 while unlinked.
    pub sequence_id: u64,
    /// The block, or an ancestor, is invalid.
    pub failed: bool,
    /// The block has been connected successfully at least once (Core: `BLOCK_VALID_SCRIPTS`).
    pub connected_once: bool,
    /// Order in which the header was accepted, for reporting the best header.
    pub header_order: u64,
}

#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    pub entries: std::collections::HashMap<Hash256, BlockEntry>,
    /// The active chain: `active[h]` is the hash of the active block at height h.
    pub active: Vec<Hash256>,
}

impl BlockTree {
    pub fn get(&self, hash: &Hash256) -> Option<&BlockEntry> {
        self.entries.get(hash)
    }

    pub fn is_active(&self, entry: &BlockEntry) -> bool {
        (entry.height as usize) < self.active.len() && self.active[entry.height as usize] == entry.hash
    }

    /// The ancestor of `hash` at `height` (the block itself at its own height). Core: `GetAncestor`.
    pub fn ancestor(&self, hash: &Hash256, height: i32) -> Option<&BlockEntry> {
        let mut entry = self.get(hash)?;
        if height < 0 || height > entry.height {
            return None;
        }
        loop {
            if entry.height == height {
                return Some(entry);
            }
            if self.is_active(entry) {
                return self.get(&self.active[height as usize]);
            }
            entry = self.get(&entry.parent?)?;
        }
    }

    pub fn tip(&self) -> &BlockEntry {
        self.get(self.active.last().expect("chain has genesis")).expect("tip is known")
    }
}
```

## 11.3 State

```rust
/// What happened to a block given to `process_block`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Stored (or, if unrequested, possibly only its header was kept; section 11.6 step 4), and not
    /// found invalid by the chain activation this call ran. A block that was not connected has not
    /// been fully validated yet.
    Accepted,
    /// The block's data was already known.
    Duplicate,
    /// The parent is unknown; the block was discarded.
    Orphan,
    /// Rejected before storage, or found invalid when chain activation tried to connect this very
    /// block; the failure's kind says whether anything was recorded (chapter 01).
    Rejected(Failure),
}

pub struct ChainState {
    pub params: NetworkParams,
    pub tree: BlockTree,
    pub utxo: UtxoSet,
    /// Linked, not known invalid blocks that are at least as good as the tip (Core: `setBlockIndexCandidates`).
    pub candidates: std::collections::HashSet<Hash256>,
    /// Blocks with data whose parent's data has not arrived, keyed by parent (Core: `m_blocks_unlinked`).
    pub unlinked: std::collections::HashMap<Hash256, Vec<Hash256>>,
    pub next_sequence_id: u64,
    pub next_header_order: u64,
    /// The most-work header not known invalid (Core: `m_best_header`). Among equal work the first
    /// accepted wins, except that a recalculation after an invalidation prefers the active tip.
    pub best_header: Hash256,
    /// Bitcoin Core's minimum chain work (`-minimumchainwork`, by default the network's
    /// `nMinimumChainWork`). Peer-to-peer policy, not consensus: it affects only unrequested blocks
    /// (section 11.6 step 4) and the peer-to-peer checks of chapter 14. The reference starts at zero,
    /// the regtest default.
    pub minimum_chain_work: U256,
}
```

## 11.4 Starting a chain

A chain starts with only the genesis block, which is linked, active and connected without touching the UTXO set (chapter 10).

```rust
impl ChainState {
    pub fn new(params: NetworkParams) -> ChainState {
        let genesis = params.genesis.clone();
        let hash = genesis.hash();
        let entry = BlockEntry {
            hash,
            header: genesis.header,
            height: 0,
            parent: None,
            chain_work: block_proof(genesis.header.bits),
            median_time_past: genesis.header.time as i64,
            block: Some(genesis),
            undo: Some(Vec::new()),
            sequence_id: 1,
            failed: false,
            connected_once: true,
            header_order: 0,
        };
        let mut tree = BlockTree::default();
        tree.entries.insert(hash, entry);
        tree.active.push(hash);
        let mut candidates = std::collections::HashSet::new();
        candidates.insert(hash);
        ChainState {
            params,
            tree,
            utxo: UtxoSet::new(),
            candidates,
            unlinked: std::collections::HashMap::new(),
            next_sequence_id: 2,
            next_header_order: 1,
            best_header: hash,
            minimum_chain_work: U256::from_u64(0),
        }
    }

    pub fn tip(&self) -> &BlockEntry {
        self.tree.tip()
    }

    /// Core: `CBlockIndexWorkComparator`, as "a is worse than b".
    fn is_worse(&self, a: &Hash256, b: &Hash256) -> bool {
        let (a, b) = (&self.tree.entries[a], &self.tree.entries[b]);
        if a.chain_work != b.chain_work {
            return a.chain_work < b.chain_work;
        }
        a.sequence_id > b.sequence_id
    }
}
```

## 11.5 Accepting a header

A header is accepted into the tree if it is not already known, passes the context-free header check, has a known parent that is not invalid, and passes the contextual header checks. A header already in the tree is accepted again silently unless it is known invalid (`duplicate-invalid`). An unknown parent makes the header an *orphan* (`prev-blk-not-found`): it is not stored. None of the failures here records anything; a known-invalid parent is reported as `bad-prevblk`. (Core: `AcceptBlockHeader`.)

```rust
/// Why a header was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Parent unknown.
    Orphan,
    Failed(Failure),
}

impl ChainState {
    /// Core: `ChainstateManager::AcceptBlockHeader`.
    pub fn accept_header(&mut self, header: &BlockHeader, now: i64) -> Result<Hash256, HeaderError> {
        let hash = header.hash();
        if hash == self.params.consensus.genesis_hash {
            return Ok(hash);
        }
        if let Some(entry) = self.tree.get(&hash) {
            if entry.failed {
                return Err(HeaderError::Failed(invalid("duplicate-invalid")));
            }
            return Ok(hash);
        }
        check_block_header(header, &self.params.consensus).map_err(HeaderError::Failed)?;
        let parent = match self.tree.get(&header.prev_block) {
            Some(parent) => parent,
            None => return Err(HeaderError::Orphan),
        };
        if parent.failed {
            return Err(HeaderError::Failed(invalid("bad-prevblk")));
        }
        contextual_check_block_header(header, parent, &self.tree, &self.params.consensus, now).map_err(HeaderError::Failed)?;

        let mut times = vec![header.time as i64];
        let mut cursor = Some(parent);
        while times.len() < MEDIAN_TIME_SPAN {
            match cursor {
                Some(entry) => {
                    times.push(entry.header.time as i64);
                    cursor = entry.parent.and_then(|p| self.tree.get(&p));
                }
                None => break,
            }
        }
        let entry = BlockEntry {
            hash,
            header: *header,
            height: parent.height + 1,
            parent: Some(parent.hash),
            chain_work: parent.chain_work.wrapping_add(block_proof(header.bits)),
            median_time_past: median_time_past(&times),
            block: None,
            undo: None,
            sequence_id: 0,
            failed: false,
            connected_once: false,
            header_order: self.next_header_order,
        };
        self.next_header_order += 1;
        let more_work = entry.chain_work > self.tree.entries[&self.best_header].chain_work;
        self.tree.entries.insert(hash, entry);
        if more_work {
            self.best_header = hash;
        }
        Ok(hash)
    }

    /// Processes headers in order, stopping at the first one not accepted.
    /// Core: `ChainstateManager::ProcessNewBlockHeaders`.
    pub fn process_headers(&mut self, headers: &[BlockHeader], now: i64) -> Result<(), (usize, HeaderError)> {
        for (index, header) in headers.iter().enumerate() {
            self.accept_header(header, now).map_err(|e| (index, e))?;
        }
        Ok(())
    }

    /// The most-work header that is not known invalid; the first accepted wins ties.
    pub fn best_header(&self) -> &BlockEntry {
        &self.tree.entries[&self.best_header]
    }

    /// Recomputes the best header after blocks were marked invalid. Bitcoin Core starts from the active
    /// tip and replaces it only with a header of strictly more work; when several other headers tie,
    /// its choice follows the iteration order of its block index, and the reference takes the first
    /// accepted. Core: `RecalculateBestHeader`.
    fn recalculate_best_header(&mut self) {
        let tip = self.tip().hash;
        self.best_header = self
            .tree
            .entries
            .values()
            .filter(|entry| !entry.failed)
            .max_by(|a, b| {
                a.chain_work
                    .cmp(&b.chain_work)
                    .then((a.hash == tip).cmp(&(b.hash == tip)))
                    .then(b.header_order.cmp(&a.header_order))
            })
            .expect("genesis is never invalid")
            .hash;
    }
}
```

## 11.6 Processing a block

Processing a full block (Core: `ProcessNewBlock`, `AcceptBlock`):

1. **Context-free body checks** (`check_block`). A failure is returned and nothing is recorded, not even the header.
2. **Header acceptance** (section 11.5). An orphan block is discarded.
3. If the block's data is already stored, nothing changes (`Duplicate`), but chain activation still runs.
4. If the block was not requested from a peer (chapter 14), only the header is kept when its chain has less work than the active tip, when it is more than 288 blocks ahead of the tip, or when its chain has less work than the minimum chain work. (Bitcoin Core also ignores an unrequested block whose data it stored before and has since pruned.) This is peer-to-peer policy that bounds resource use, but it is observable: a block reduced to its header is linked only when its data arrives again, so it can change sequence numbers and with them the choice between equal-work chains. Chapter 14 adds one more peer-to-peer rule for blocks whose header is new (`p2p_block_work_acceptable`).
5. **Contextual body checks** (`contextual_check_block`). On an `Invalid` failure, the block and all its descendants are marked invalid. On a `Mutated` failure nothing is recorded.
6. The block's data is stored. If its parent is linked (or it is genesis), it becomes linked with the next sequence number, and so does every stored descendant that was waiting for it, breadth first. Each newly linked block becomes a candidate for the active tip unless it is worse than the current tip.
7. **Chain activation** (section 11.7).

```rust
/// Core: `MIN_BLOCKS_TO_KEEP`.
pub const MIN_BLOCKS_TO_KEEP: i32 = 288;

impl ChainState {
    /// Core: `ChainstateManager::ProcessNewBlock`. `requested` is false only for blocks a peer sent
    /// without being asked (chapter 14); block submission by an operator counts as requested.
    pub fn process_block(&mut self, block: Block, now: i64, requested: bool) -> BlockOutcome {
        if let Err(failure) = check_block(&block, &self.params.consensus) {
            return BlockOutcome::Rejected(failure);
        }
        let hash = match self.accept_header(&block.header, now) {
            Ok(hash) => hash,
            Err(HeaderError::Orphan) => return BlockOutcome::Orphan,
            Err(HeaderError::Failed(failure)) => return BlockOutcome::Rejected(failure),
        };
        if self.tree.entries[&hash].block.is_some() {
            self.activate_best_chain();
            return BlockOutcome::Duplicate;
        }
        if !requested {
            let entry = &self.tree.entries[&hash];
            let tip = self.tip();
            if entry.chain_work < tip.chain_work
                || entry.height > tip.height + MIN_BLOCKS_TO_KEEP
                || entry.chain_work < self.minimum_chain_work
            {
                self.activate_best_chain();
                return BlockOutcome::Accepted;
            }
        }
        let parent_hash = self.tree.entries[&hash].parent;
        let result = {
            let parent = parent_hash.and_then(|p| self.tree.get(&p));
            contextual_check_block(&block, parent, &self.params.consensus)
        };
        if let Err(failure) = result {
            if failure.kind != FailureKind::Mutated {
                self.mark_invalid(&hash);
            }
            return BlockOutcome::Rejected(failure);
        }
        self.tree.entries.get_mut(&hash).unwrap().block = Some(block);
        self.link(hash);
        // Report a failure of this very block; a failure of an ancestor leaves the outcome
        // `Accepted` (Bitcoin Core's block submission answers "inconclusive" then).
        match self.activate_best_chain().into_iter().find(|(failed, _)| *failed == hash) {
            Some((_, failure)) => BlockOutcome::Rejected(failure),
            None => BlockOutcome::Accepted,
        }
    }

    /// Assigns sequence numbers to `hash` and any waiting descendants, or queues it until its parent
    /// is linked. Core: `ChainstateManager::ReceivedBlockTransactions`.
    fn link(&mut self, hash: Hash256) {
        let parent = self.tree.entries[&hash].parent;
        let parent_linked = parent.map_or(true, |p| self.tree.entries[&p].sequence_id != 0);
        if !parent_linked {
            let parent = parent.unwrap();
            if !self.tree.entries[&parent].failed {
                self.unlinked.entry(parent).or_default().push(hash);
            }
            return;
        }
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(hash);
        while let Some(current) = queue.pop_front() {
            self.tree.entries.get_mut(&current).unwrap().sequence_id = self.next_sequence_id;
            self.next_sequence_id += 1;
            if !self.is_worse(&current, &self.tip().hash.clone()) {
                self.candidates.insert(current);
            }
            if let Some(children) = self.unlinked.remove(&current) {
                queue.extend(children);
            }
        }
    }

    /// Marks a block and all its known descendants invalid. Core: `InvalidBlockFound`,
    /// `InvalidChainFound`, `SetBlockFailureFlags`.
    fn mark_invalid(&mut self, hash: &Hash256) {
        let height = self.tree.entries[hash].height;
        let descendants: Vec<Hash256> = self
            .tree
            .entries
            .values()
            .filter(|entry| entry.height >= height && self.tree.ancestor(&entry.hash, height).map(|a| a.hash) == Some(*hash))
            .map(|entry| entry.hash)
            .collect();
        for descendant in descendants {
            self.tree.entries.get_mut(&descendant).unwrap().failed = true;
        }
        self.candidates.remove(hash);
        if self.tree.entries[&self.best_header].failed {
            self.recalculate_best_header();
        }
    }
}
```

## 11.7 Chain activation

Activation repeats until the active tip is the best candidate:

1. Pick the best candidate (most work, then lowest sequence number). Walk from it back to the active chain; if any block on the way is known invalid or lacks data, remove the candidates on that path and pick again. If no candidate remains, or the best is the tip, stop.
2. Disconnect blocks from the tip down to the fork point (the last block shared with the candidate's chain), restoring the UTXO set from undo data.
3. Connect the candidate's blocks one by one (chapter 10, `connect_block`). After each success, drop candidates that are now worse than the tip. On a failure, mark the block and its descendants invalid and go back to step 1 (the node may then return to its previous chain, or stop part way along the new one if that is now the best valid chain). Disconnecting a block does not remove it from the candidates; the old tip leaves the candidate set only when a better block (more work, or equal work and a lower sequence number) becomes the tip. That is what lets the node return to its previous chain after a failed reorganization.

(Core: `ActivateBestChain`, `ActivateBestChainStep`, `FindMostWorkChain`, `PruneBlockIndexCandidates`, `ConnectTip`, `DisconnectTip`.)

```rust
impl ChainState {
    /// Core: `Chainstate::FindMostWorkChain`.
    fn find_most_work_chain(&mut self) -> Option<Hash256> {
        loop {
            let mut best: Option<Hash256> = None;
            for candidate in &self.candidates {
                best = match best {
                    None => Some(*candidate),
                    Some(current) if self.is_worse(&current, candidate) => Some(*candidate),
                    keep => keep,
                };
            }
            let best = best?;
            let mut test = best;
            let mut bad_path = false;
            loop {
                let entry = &self.tree.entries[&test];
                if self.tree.is_active(entry) {
                    break;
                }
                if entry.failed || entry.block.is_none() {
                    let mut failed = best;
                    while failed != test {
                        self.candidates.remove(&failed);
                        failed = self.tree.entries[&failed].parent.unwrap();
                    }
                    self.candidates.remove(&test);
                    bad_path = true;
                    break;
                }
                test = entry.parent.expect("non-active block has a parent");
            }
            if !bad_path {
                return Some(best);
            }
        }
    }

    /// Core: `Chainstate::PruneBlockIndexCandidates`.
    fn prune_candidates(&mut self) {
        let tip = self.tip().hash;
        let worse: Vec<Hash256> = self.candidates.iter().filter(|c| self.is_worse(c, &tip)).copied().collect();
        for candidate in worse {
            self.candidates.remove(&candidate);
        }
    }

    /// Core: `Chainstate::ConnectTip`.
    fn connect_tip(&mut self, hash: &Hash256) -> Result<(), Failure> {
        let entry = &self.tree.entries[hash];
        let block = entry.block.as_ref().expect("candidate has data");
        let (changes, undo) = connect_block(block, entry, &self.tree, &self.utxo, &self.params.consensus)?;
        UtxoView::apply(changes, &mut self.utxo);
        let entry = self.tree.entries.get_mut(hash).unwrap();
        entry.undo = Some(undo);
        entry.connected_once = true;
        self.tree.active.push(*hash);
        Ok(())
    }

    /// Core: `Chainstate::DisconnectTip`, `DisconnectBlock`.
    fn disconnect_tip(&mut self) {
        let hash = self.tree.active.pop().expect("never disconnect genesis");
        assert!(!self.tree.active.is_empty(), "never disconnect genesis");
        let entry = &self.tree.entries[&hash];
        let block = entry.block.as_ref().unwrap();
        let undo = entry.undo.as_ref().unwrap();
        for (index, tx) in block.transactions.iter().enumerate().rev() {
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if !is_unspendable(&output.script_pubkey) {
                    self.utxo.remove(&OutPoint { txid, vout: vout as u32 });
                }
            }
            if index > 0 {
                for (input, coin) in tx.inputs.iter().zip(undo[index - 1].iter()).rev() {
                    self.utxo.insert(input.prevout, coin.clone());
                }
            }
        }
    }

    /// The last block of the active chain that is an ancestor of (or is) `hash`. Core: `CChain::FindFork`.
    pub fn find_fork(&self, hash: &Hash256) -> Hash256 {
        let mut entry = &self.tree.entries[hash];
        while !self.tree.is_active(entry) {
            entry = &self.tree.entries[&entry.parent.unwrap()];
        }
        entry.hash
    }

    /// Core: `Chainstate::ActivateBestChain`.
    /// Returns the blocks that failed to connect, with their failures.
    pub fn activate_best_chain(&mut self) -> Vec<(Hash256, Failure)> {
        let mut failures = Vec::new();
        loop {
            let best = match self.find_most_work_chain() {
                Some(best) => best,
                None => return failures,
            };
            if best == self.tip().hash {
                return failures;
            }
            let fork = self.find_fork(&best);
            while self.tip().hash != fork {
                self.disconnect_tip();
            }
            let fork_height = self.tree.entries[&fork].height;
            let best_height = self.tree.entries[&best].height;
            let path: Vec<Hash256> = (fork_height + 1..=best_height)
                .map(|h| self.tree.ancestor(&best, h).unwrap().hash)
                .collect();
            for hash in path {
                match self.connect_tip(&hash) {
                    Ok(()) => self.prune_candidates(),
                    Err(failure) => {
                        self.mark_invalid(&hash);
                        failures.push((hash, failure));
                        break;
                    }
                }
            }
        }
    }
}
```

## 11.8 Mutated blocks

These failures are `Mutated`, meaning the bytes received do not match what the header commits to, and MUST NOT be recorded against the block hash (Core: the results with `BlockValidationResult::BLOCK_MUTATED`):

- `bad-txnmrklroot`: the transactions do not hash to the header's merkle root;
- `bad-txns-duplicate`: the merkle tree is mutated (section 10.2);
- `bad-witness-nonce-size`, `bad-witness-merkle-match`, `unexpected-witness`: witness data does not match the commitment, or is present without one;
- any failure to decode the block.

Weight is checked after the witness commitment for the same reason (chapter 10). A peer that sends a mutated block is misbehaving and may be disconnected, but the block hash stays acceptable.

## 11.9 Invalidating a block by operator decision

Operators (and Bitcoin Core's functional tests) can declare a block invalid. The block and all its descendants are marked invalid; if the block is on the active chain, blocks are disconnected down to its parent; every linked, not invalid block that is not worse than the new tip becomes a candidate again; and chain activation runs. The genesis block cannot be invalidated. (Core: `InvalidateBlock` followed by `ActivateBestChain`, as the `invalidateblock` RPC does.)

```rust
impl ChainState {
    /// Core: `Chainstate::InvalidateBlock` and `ActivateBestChain`.
    pub fn invalidate_block(&mut self, hash: &Hash256) {
        if *hash == self.params.consensus.genesis_hash || !self.tree.entries.contains_key(hash) {
            return;
        }
        while self.tree.is_active(&self.tree.entries[hash]) {
            let disconnected = self.tip().hash;
            self.disconnect_tip();
            self.tree.entries.get_mut(&disconnected).unwrap().failed = true;
            self.candidates.remove(&disconnected);
        }
        self.mark_invalid(hash);
        let tip = self.tip().hash;
        self.candidates.insert(tip);
        let eligible: Vec<Hash256> = self
            .tree
            .entries
            .values()
            .filter(|entry| entry.block.is_some() && !entry.failed && entry.sequence_id != 0)
            .map(|entry| entry.hash)
            .filter(|h| !self.is_worse(h, &tip))
            .collect();
        self.candidates.extend(eligible);
        self.activate_best_chain();
    }
}
```

## 11.10 Reporting chain tips

For diagnostics, Bitcoin Core's `getchaintips` reports the active tip and every block that is not on the active chain and has no child outside it, with a status: `active`, `invalid`, `headers-only` (not linked), `valid-fork` (connected at some point), or `valid-headers` (linked but never connected). (Core: `getchaintips`, `src/rpc/blockchain.cpp`.)

```rust
impl ChainState {
    /// Returns (hash, height, status) for every chain tip.
    pub fn chain_tips(&self) -> Vec<(Hash256, i32, &'static str)> {
        let mut has_inactive_child = std::collections::HashSet::new();
        for entry in self.tree.entries.values() {
            if !self.tree.is_active(entry) {
                if let Some(parent) = entry.parent {
                    has_inactive_child.insert(parent);
                }
            }
        }
        let mut tips = Vec::new();
        for entry in self.tree.entries.values() {
            let is_tip = if self.tree.is_active(entry) {
                entry.hash == self.tip().hash
            } else {
                !has_inactive_child.contains(&entry.hash)
            };
            if !is_tip {
                continue;
            }
            let status = if self.tree.is_active(entry) {
                "active"
            } else if entry.failed {
                "invalid"
            } else if entry.sequence_id == 0 {
                "headers-only"
            } else if entry.connected_once {
                "valid-fork"
            } else {
                "valid-headers"
            };
            tips.push((entry.hash, entry.height, status));
        }
        tips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        tips
    }
}
```

## 11.11 Blocks received from peers

Before handing a block received from a peer to `process_block`, Bitcoin Core discards it outright, recording nothing at all, if its parent is known and the block is *mutated* by this definition (Core: `IsBlockMutated`, called from `PeerManagerImpl::ProcessMessage`):

- its merkle root does not match, or its merkle tree is mutated;
- it has no coinbase as first transaction and some transaction's stripped serialization is exactly 64 bytes long (such a transaction could be an inner node of a merkle tree in disguise);
- its witness data fails the commitment rules of chapter 10, with the commitment expected if segwit is active at the block's height.

This pre-check never changes the chain selected; it only avoids storing the header of a block whose body was corrupted in transit.

```rust
/// Core: `IsBlockMutated`.
pub fn is_block_mutated(block: &Block, check_witness_root: bool) -> bool {
    let (root, tree_mutated) = block_merkle_root(block);
    if root != block.header.merkle_root || tree_mutated {
        return true;
    }
    if block.transactions.is_empty() || !block.transactions[0].is_coinbase() {
        return block.transactions.iter().any(|tx| tx.stripped_size() == 64);
    }
    check_witness_malleation(block, check_witness_root).is_err()
}
```

## 11.12 What a real node adds

The reference keeps everything in memory and validates one block at a time. A production node also persists the block tree, block data, undo data and the UTXO set, recovers from crashes, prunes old blocks, validates scripts in parallel, and caches signature checks. Each of these is safe exactly when it is invisible: the node MUST behave as if every block were processed by `process_block` in the order received. A restart is the one exception Bitcoin Core itself makes: it keeps its active chain but forgets the order in which other equal-work chains arrived (section 11.1, rule 2). Appendix B lists the specific traps (batching across blocks, caches keyed by txid instead of wtxid, defaults for missing data, out-of-order connection).

*Assume-valid.* Bitcoin Core skips script verification for blocks that are ancestors of a hard-coded block hash (block 966143 on mainnet in v32.1), under conditions spelled out in `ConnectBlock` (the block is on the best header chain, that chain has at least the minimum chain work, and the block is more than two weeks of work below the best header). Every other rule is still checked. This is an optimization based on trust in the software release, not a consensus rule; implementations MAY adopt it, and SHOULD offer a way to verify every script.
