TARGET_WASI:=--target wasm32-wasip2
TARGET_BROWSER:=--target wasm32-unknown-unknown
QUIET_WARN:=RUSTFLAGS="-Awarnings"

ifneq ($(filter quiet,$(MAKECMDGOALS)),)
CARGO_ENV:=$(QUIET_WARN)
else
CARGO_ENV:=
endif

_sync_version:
	@cargo set-version ${__VERSION}

quiet:
	@true

_init:
	@jq -r '.TECHNO_INIT_DIRS[] | "mkdir -p \(.)"' .technoproj | sh

define cargo_targets  # $(1)=command, $(2)=extra flags
$(1)_native:
	$(CARGO_ENV) cargo $(1)
$(1)_wasi:
	$(CARGO_ENV) cargo $(1) $(TARGET_WASI)
$(1)_browser:
	$(CARGO_ENV) cargo $(1) $(TARGET_BROWSER)
$(1): $(1)_native $(1)_wasi $(1)_browser
endef

$(eval $(call cargo_targets,build))
$(eval $(call cargo_targets,check))
$(eval $(call cargo_targets,test))

check: check_native check_wasi check_browser
test: test_native test_wasi test_browser
build: build_native build_wasi build_browser

clean:
	cargo clean
	rm -rf target .data

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	cargo doc --no-deps --open

all: check test build

ci: fmt clippy check test