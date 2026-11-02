// plugin/src/lib.rs
// License: Apache-2.0
//
// Entry points: one extism export per function the generated Python and
// TypeScript bindings call, named as they call it (generator/wire.py), from
// the list build.rs generates out of the schema. Each export reads the raw
// request, hands it to the matching adapter in aloecrypt_core::plugin::exports,
// and returns the status-prefixed reply. The adapters own the wire format;
// this crate only moves bytes across the extism boundary.
//
// Build: cargo build -p aloecrypt_plugin --release --target wasm32-wasip1

macro_rules! extism_exports {
    ($($name:ident,)*) => {$(
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() -> i32 {
            let reply = aloecrypt_core::plugin::exports::$name(&extism_pdk::input_bytes());
            match extism_pdk::output(reply) {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
    )*};
}

aloecrypt_core::for_each_plugin_export!(extism_exports);
