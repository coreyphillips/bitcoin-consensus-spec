# Block corpus recorder for Bitcoin Core v32.1.
#
#   make all CORE_SRC=/path/to/bitcoin-v32.1-checkout -j4
#
# builds the image, records every scenario twice with the same seeds, compares
# the two recordings, writes the corpus to ../vectors/blocks, replays it through
# the Core chain harness and writes REPORT.md. See README.md.

SHELL := /bin/bash
IMAGE ?= bcs-recorder:32.1
RELEASE_DIR ?= $(HOME)/bcs-data/bin
CORE_SRC ?=
WORK ?= $(CURDIR)/work
VECTORS ?= $(abspath $(CURDIR)/../vectors/blocks)
SEED ?= 1
TIMEOUT_FACTOR ?= 4
REPLAY_JOBS ?= 6
EXTRA_DOCKER_ARGS ?=

TESTS := feature_block feature_taproot p2p_segwit feature_segwit p2p_invalid_block \
         feature_cltv feature_dersig feature_nulldummy feature_csv_activation \
         feature_bip68_sequence mining_basic

ARGS_feature_block := --skipreorg
# Nodes written to the corpus (default 0). mining_basic node 2 is pruned and excluded.
NODES_feature_segwit := 0,1,2
NODES_p2p_segwit := 0,1
NODES_feature_bip68_sequence := 0,1
NODES_mining_basic := 0,1
PAIRS := $(foreach t,$(TESTS),$(t):$(or $(NODES_$(t)),0))
# $(1): recording (run1 or run2), $(2): extra postprocess.py arguments.
POSTPROCESS_ALL = for tn in $(PAIRS); do python3 postprocess.py --raw /work/raw/$(1)/$${tn%%:*} --scenario $${tn%%:*} --nodes $${tn\#*:} $(2); done
COMMON_ARGS := --randomseed=$(SEED) --portseed=$(SEED) --v1transport --timeout-factor=$(TIMEOUT_FACTOR)

IMAGE_ID = $(shell docker image inspect --format '{{.Id}}' $(IMAGE) 2>/dev/null)
# Recording needs the Core source tree; replaying and reporting do not.
RUN = docker run --rm $(EXTRA_DOCKER_ARGS) -e BCS_IMAGE_ID=$(IMAGE_ID) -v $(CORE_SRC):/core:ro -v $(WORK):/work -v $(VECTORS):/vectors $(IMAGE)
VRUN = docker run --rm $(EXTRA_DOCKER_ARGS) -v $(WORK):/work -v $(VECTORS):/vectors -v $(CURDIR):/out $(IMAGE)

.PHONY: all image dirs check-src record record2 compare corpus verify verify-noop report reorg clean

# Stages run in order; `-j` parallelizes the recordings within a stage.
all:
	$(MAKE) image
	$(MAKE) record record2
	$(MAKE) compare
	$(MAKE) corpus
	$(MAKE) verify
	$(MAKE) verify-noop
	$(MAKE) report

dirs:
	@test -n "$(WORK)" && test -n "$(VECTORS)" || { echo "WORK and VECTORS must be set"; exit 1; }
	@mkdir -p $(WORK)/logs $(VECTORS)

check-src: dirs
	@test -n "$(CORE_SRC)" || { echo "set CORE_SRC to a Bitcoin Core v32.1 source checkout"; exit 1; }
	@test -f "$(CORE_SRC)/test/functional/test_framework/test_framework.py" || { echo "CORE_SRC has no test/functional"; exit 1; }

image:
	docker build --build-context release=$(RELEASE_DIR) -t $(IMAGE) .

# One target per scenario and recording, so `make -j4 record` runs in parallel.
record: $(foreach t,$(TESTS),$(WORK)/raw/run1/$(t)/.done)
record2: $(foreach t,$(TESTS),$(WORK)/raw/run2/$(t)/.done)

$(WORK)/raw/run1/%/.done: | check-src
	rm -rf $(WORK)/raw/run1/$* $(WORK)/scratch/run1/$*
	$(RUN) python3 record.py --test $*.py --out /work/raw/run1/$* --work /work/scratch/run1/$* -- \
	  $(COMMON_ARGS) $(ARGS_$*) > $(WORK)/logs/run1-$*.log 2>&1 || { tail -40 $(WORK)/logs/run1-$*.log; exit 1; }
	touch $@

$(WORK)/raw/run2/%/.done: | check-src
	rm -rf $(WORK)/raw/run2/$* $(WORK)/scratch/run2/$*
	$(RUN) python3 record.py --test $*.py --out /work/raw/run2/$* --work /work/scratch/run2/$* -- \
	  $(COMMON_ARGS) $(ARGS_$*) > $(WORK)/logs/run2-$*.log 2>&1 || { tail -40 $(WORK)/logs/run2-$*.log; exit 1; }
	touch $@

# Both recordings are post-processed without racy marks and compared.
compare: $(WORK)/racy.json

$(WORK)/racy.json: $(foreach t,$(TESTS),$(WORK)/raw/run1/$(t)/.done $(WORK)/raw/run2/$(t)/.done)
	rm -rf $(WORK)/corpus/run1 $(WORK)/corpus/run2
	$(VRUN) bash -c 'set -e; $(call POSTPROCESS_ALL,run1,--out-dir /work/corpus/run1) > /dev/null'
	$(VRUN) bash -c 'set -e; $(call POSTPROCESS_ALL,run2,--out-dir /work/corpus/run2) > /dev/null'
	$(VRUN) python3 compare_runs.py --a /work/corpus/run1 --b /work/corpus/run2 --out /work/racy.json --report /work/compare.json

# The committed corpus comes from the first recording, with racy checks marked.
corpus: $(WORK)/racy.json | dirs
	rm -f $(VECTORS)/*.jsonl.gz $(WORK)/stats.jsonl
	rm -rf $(VECTORS)/blobs
	$(VRUN) bash -c 'set -e; $(call POSTPROCESS_ALL,run1,--out-dir /vectors --racy /work/racy.json --stats /work/stats.jsonl)'

verify: | dirs
	$(VRUN) bash -c 'python3 replay.py --jobs $(REPLAY_JOBS) --json /work/verify.json /vectors/*.jsonl.gz'

# Same replay, treating restarts with unchanged options as no-ops (CORPUS.md allows both).
verify-noop: | dirs
	$(VRUN) bash -c 'python3 replay.py --jobs $(REPLAY_JOBS) --restart-mode noop-if-same --json /work/verify-noop.json /vectors/*.jsonl.gz'

report: | dirs
	$(VRUN) python3 report.py --stats /work/stats.jsonl --compare /work/compare.json --verify /work/verify.json \
	  --verify-noop /work/verify-noop.json --vectors /vectors --out /out/REPORT.md

# Optional: feature_block including the 1088-block reorg (over 1 GB of block
# data). Written to $(WORK)/reorg, never to the committed corpus.
reorg: | check-src
	rm -rf $(WORK)/raw/reorg/feature_block $(WORK)/scratch/reorg/feature_block $(WORK)/reorg
	$(RUN) python3 record.py --test feature_block.py --out /work/raw/reorg/feature_block --work /work/scratch/reorg/feature_block -- \
	  $(COMMON_ARGS) > $(WORK)/logs/reorg-feature_block.log 2>&1
	$(VRUN) bash -c 'python3 postprocess.py --raw /work/raw/reorg/feature_block --scenario feature_block_reorg --out-dir /work/reorg --blob-threshold 100000 && \
	  python3 replay.py --json /work/verify-reorg.json /work/reorg/feature_block_reorg.node0.jsonl.gz'

clean:
	@test -n "$(WORK)" || { echo "WORK must be set"; exit 1; }
	rm -rf $(WORK)
