ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=.technoproj

-include script/version.mk
-include script/cargo_rs.mk

# build.rs merges config/api_core.json with doc/api_core_docs.json itself and
# writes .generated/api_core_merged.json, so a clean checkout builds with no
# preparatory step and no jq on the path. Kept as an alias for muscle memory.
merge_docs:
	@cargo build --lib

echo:
	@echo ${__VERSION}

# The generators read the merged schema that build.rs emits.
generate: merge_docs
	@python3 ./generator/gen_py.py

build:
	@cargo build --profile release

align:
	@cargo run --profile release --bin align