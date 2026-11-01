// src/bin/merge_schema.rs
// License: Apache-2.0
//
// Entry point: `merge_schema [PATH]` writes the merged API schema to PATH
// (default `.generated/api_core_merged.json`), creating its directory.
//
// build.rs merges config/api_core.json with doc/api_core_docs.json and writes
// the result to OUT_DIR, because a build script may not write into the source
// tree. The Python and TypeScript generators read it from disk, so this copies
// that build output to where they look. `make merge_docs` runs it.

use std::{env, fs, path::Path, process::ExitCode};

const DEFAULT_PATH: &str = ".generated/api_core_merged.json";
const MERGED: &str = include_str!(concat!(env!("OUT_DIR"), "/api_core_merged.json"));

fn main() -> ExitCode {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_PATH.to_string());
    let path = Path::new(&path);
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("merge_schema: cannot create {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = fs::write(path, MERGED) {
        eprintln!("merge_schema: cannot write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
