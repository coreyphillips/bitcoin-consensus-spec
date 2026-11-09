# Block corpus recorder for Bitcoin Core v32.1.
#
#   make all CORE_SRC=/path/to/bitcoin-v32.1-checkout -j6
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

# A scenario is one recorded test run. Per scenario: TESTFILE_ (default
# <scenario>.py in Core's test/functional; extra/ means this directory),
# ARGS_ (test arguments), NODES_ (nodes written to the corpus, default 0) and
# BLOB_ (raw size above which blocks go to sidecar blobs, default 1,000,000).
SCENARIOS := feature_block feature_block_reorg feature_taproot p2p_segwit feature_segwit \
             p2p_invalid_block feature_cltv feature_dersig feature_nulldummy \
             feature_csv_activation feature_bip68_sequence mining_basic feature_spec_pitfalls

ARGS_feature_block := --skipreorg
TESTFILE_feature_block_reorg := feature_block.py
BLOB_feature_block_reorg := 100000
TESTFILE_feature_spec_pitfalls := extra/feature_spec_pitfalls.py
# mining_basic node 2 is pruned and excluded.
NODES_feature_segwit := 0,1,2
NODES_p2p_segwit := 0,1
NODES_feature_bip68_sequence := 0,1
NODES_mining_basic := 0,1

COMMON_ARGS := --randomseed=$(SEED) --portseed=$(SEED) --v1transport --timeout-factor=$(TIMEOUT_FACTOR)
# $(1): recording (run1 or run2), $(2): extra postprocess.py arguments.
POSTPROCESS_ALL = $(foreach s,$(SCENARIOS),python3 postprocess.py --raw /work/raw/$(1)/$(s) --scenario $(s) \
  --nodes $(or $(NODES_$(s)),0) $(if $(BLOB_$(s)),--blob-threshold $(BLOB_$(s))) $(2) &&) true

IMAGE_ID = $(shell docker image inspect --format '{{.Id}}' $(IMAGE) 2>/dev/null)
# Recording needs the Core source tree; replaying and reporting do not.
RUN = docker run --rm $(EXTRA_DOCKER_ARGS) -e BCS_IMAGE_ID=$(IMAGE_ID) -v $(CORE_SRC):/core:ro -v $(WORK):/work -v $(VECTORS):/vectors $(IMAGE)
VRUN = docker run --rm $(EXTRA_DOCKER_ARGS) -v $(WORK):/work -v $(VECTORS):/vectors -v $(CURDIR):/out $(IMAGE)

.PHONY: all image dirs check-src record record2 compare corpus verify verify-noop report clean

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

# One target per scenario and recording, so `make -j6 record record2` runs in parallel.
record: $(foreach s,$(SCENARIOS),$(WORK)/raw/run1/$(s)/.done)
record2: $(foreach s,$(SCENARIOS),$(WORK)/raw/run2/$(s)/.done)

$(WORK)/raw/run1/%/.done: | check-src
	rm -rf $(WORK)/raw/run1/$* $(WORK)/scratch/run1/$*
	$(RUN) python3 record.py --test $(or $(TESTFILE_$*),$*.py) --out /work/raw/run1/$* --work /work/scratch/run1/$* -- \
	  $(COMMON_ARGS) $(ARGS_$*) > $(WORK)/logs/run1-$*.log 2>&1 || { tail -40 $(WORK)/logs/run1-$*.log; exit 1; }
	touch $@

$(WORK)/raw/run2/%/.done: | check-src
	rm -rf $(WORK)/raw/run2/$* $(WORK)/scratch/run2/$*
	$(RUN) python3 record.py --test $(or $(TESTFILE_$*),$*.py) --out /work/raw/run2/$* --work /work/scratch/run2/$* -- \
	  $(COMMON_ARGS) $(ARGS_$*) > $(WORK)/logs/run2-$*.log 2>&1 || { tail -40 $(WORK)/logs/run2-$*.log; exit 1; }
	touch $@

# Both recordings are post-processed without racy marks and compared.
compare: $(WORK)/racy.json

$(WORK)/racy.json: $(foreach s,$(SCENARIOS),$(WORK)/raw/run1/$(s)/.done $(WORK)/raw/run2/$(s)/.done)
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

clean:
	@test -n "$(WORK)" || { echo "WORK must be set"; exit 1; }
	rm -rf $(WORK)
