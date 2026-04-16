ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=.technoproj

-include script/version.mk
-include script/cargo_rs.mk

merge_docs:
	@mkdir -p .generated
	@jq -s -f ./doc/merge_docs.jq ./config/api_core.json ./doc/api_core_docs.json > ./.generated/api_core_merged.json
	@echo "Created: ./.generated/api_core_merged.json"

echo:
	@echo ${__VERSION}

generate:
	@python3 ./generator/gen_py.py

build:
	@cargo build --profile release

align:
	@cargo run --profile release --bin align