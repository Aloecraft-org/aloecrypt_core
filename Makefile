ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=.technoproj

-include script/version.mk
-include script/cargo_rs.mk

MERGED_SCHEMA:=.generated/api_core_merged.json

# build.rs merges config/api_core.json with doc/api_core_docs.json and writes
# the result to OUT_DIR, since a build script may not write into the source
# tree. The generators read it from disk, so the merge_schema binary copies it
# to $(MERGED_SCHEMA). Cargo rebuilds it whenever the schema or docs change.
merge_docs:
	@cargo run --quiet --bin merge_schema -- $(MERGED_SCHEMA)

echo:
	@echo ${__VERSION}

# Validate the schema before generating from it: names are matched with no
# validation, so an unresolved one is silently skipped rather than failing.
lint: merge_docs
	@python3 ./generator/lint_schema.py

# The generators read the merged schema that build.rs emits.
generate: lint
	@python3 ./generator/gen_py.py
	@python3 ./generator/gen_ts.py

# Type-check the generated TypeScript and run it against a stub plugin.
check_ts: generate
	@cd .generated/gen_ts && tsc --strict --target es2020 --module es2020 --outDir out aloecrypt_core.ts
	@mv .generated/gen_ts/out/aloecrypt_core.js .generated/gen_ts/out/aloecrypt_core.mjs
	@node ./generator/check_ts.mjs .generated/gen_ts/out/aloecrypt_core.mjs

# The extism plugin the generated bindings load (plugin/), and the end-to-end
# check that drives it through the real Python bindings (needs `pip install
# extism`).
PLUGIN_WASM:=target/wasm32-wasip1/release/aloecrypt_plugin.wasm

.PHONY: plugin check_plugin
plugin:
	@cargo build --release -p aloecrypt_plugin --target wasm32-wasip1

check_plugin: generate plugin
	@python3 ./generator/check_plugin.py $(PLUGIN_WASM)

build:
	@cargo build --profile release

align:
	@cargo run --profile release --bin align