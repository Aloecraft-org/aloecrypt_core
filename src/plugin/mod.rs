pub use super::*;

pub mod pqc;

// The wire-format adapters behind every plugin export, generated from the
// schema by build.rs. The aloecrypt_plugin crate turns each into an extism
// export; with the feature off none of this is compiled.
#[cfg(feature = "plugin")]
pub mod wire;

#[cfg(feature = "plugin")]
#[allow(non_snake_case, clippy::all)]
pub mod exports {
    use super::wire;
    #[allow(unused_imports)]
    use crate::*;
    include!(concat!(env!("OUT_DIR"), "/plugin_exports.rs"));
}
