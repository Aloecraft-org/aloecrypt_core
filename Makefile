ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=.technoproj

-include script/version.mk
-include script/cargo_rs.mk

MERGED_SCHEMA:=.generated/api_core_merged.json

# build.rs merges config/api_core.json with doc/api_core_docs.json itself and
# writes .generated/api_core_merged.json, so a clean checkout builds with no
# preparatory step and no jq on the path. Kept as an alias for muscle memory.
#
# The merged schema is a side effect that cargo does not track: it reruns
# build.rs only when config/ or doc/ change. A warm target directory with an
# absent .generated -- which is gitignored, and is exactly what a restored
# cargo cache in CI looks like -- leaves the file missing and the build a
# no-op. Touching build.rs forces the rerun that rewrites it.
merge_docs:
	@test -f $(MERGED_SCHEMA) || touch build.rs
	@cargo build --lib

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

build:
	@cargo build --profile release

align:
	@cargo run --profile release --bin align