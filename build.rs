#![allow(warnings)]

use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

fn generate_sz_consts(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            writeln!(
                out,
                "{}pub const {} : usize = {};",
                indent,
                entry["name"].as_str().unwrap(),
                entry["value"].as_str().unwrap()
            );
        }
    }
}

fn generate_empty_consts(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            writeln!(
                out,
                "{}pub const {} : [u8; {}] = [0u8; {}];",
                indent,
                entry["name"].as_str().unwrap(),
                entry["size"].as_str().unwrap(),
                entry["size"].as_str().unwrap(),
            );
        }
    }
}

fn generate_byte_aliases(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            let mut byte_type = "u8";
            if let Some(is_signed_str) = entry["signed"].as_str() {
                if is_signed_str == "true" {
                    byte_type = "i8";
                }
            }
            writeln!(
                out,
                "{}pub type {} = [{}; {}];",
                indent,
                entry["name"].as_str().unwrap(),
                byte_type,
                entry["length"].as_str().unwrap(),
            );
        }
    }
}

fn generate_functions(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            // writeln!(out, "{}pub const {} : usize = {};" , indent, entry["name"], entry["value"]);
        }
    }
}

fn generate_enums(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";

    if let Some(enums) = value.as_array() {
        for enum_entry in enums {
            writeln!(out);
            if let Some(derives) = enum_entry["derives"].as_str() {
                writeln!(out, "{}#[derive({})]", indent, derives).unwrap();
            }
            writeln!(out, "{}#[repr(transparent)]", indent).unwrap();
            writeln!(
                out,
                "{}pub struct {}(pub {});",
                indent,
                enum_entry["name"].as_str().unwrap(),
                enum_entry["repr_type"].as_str().unwrap()
            )
            .unwrap();

            writeln!(out);
            writeln!(
                out,
                "{}#[derive(Debug, Clone, Copy, PartialEq, Eq)]",
                indent
            )
            .unwrap();
            writeln!(
                out,
                "{}#[repr({})]",
                indent,
                enum_entry["repr_type"].as_str().unwrap()
            )
            .unwrap();
            writeln!(
                out,
                "{}pub enum {}Enum {{",
                indent,
                enum_entry["name"].as_str().unwrap()
            )
            .unwrap();
            let indent = "        ";
            for c in enum_entry["members"].as_array().unwrap() {
                writeln!(out, "        /// {},", c["description"].as_str().unwrap());
                writeln!(
                    out,
                    "{}{} = {},",
                    indent,
                    c["name"].as_str().unwrap(),
                    c["discriminant"].as_str().unwrap()
                )
                .unwrap();
            }
            let indent = "    ";
            writeln!(out, "{}}}", indent);
            writeln!(out);

            writeln!(out);
            writeln!(
                out,
                "{}impl Into<{}> for {}Enum {{",
                indent,
                enum_entry["name"].as_str().unwrap(),
                enum_entry["name"].as_str().unwrap()
            )
            .unwrap();
            let indent = "        ";
            writeln!(
                out,
                "{}fn into(self) -> {} {{",
                indent,
                enum_entry["name"].as_str().unwrap(),
            );
            let indent = "            ";
            writeln!(out, "{}match self {{", indent);

            let indent = "                ";
            for c in enum_entry["members"].as_array().unwrap() {
                writeln!(
                    out,
                    "{}{}Enum::{} => {}({}),",
                    indent,
                    enum_entry["name"].as_str().unwrap(),
                    c["name"].as_str().unwrap(),
                    enum_entry["name"].as_str().unwrap(),
                    c["discriminant"].as_str().unwrap()
                );
            }
            let indent = "            ";
            writeln!(out, "{}}}", indent);
            let indent = "        ";
            writeln!(out, "{}}}", indent);
            let indent = "    ";
            writeln!(out, "{}}}", indent);
            writeln!(out);

            writeln!(
                out,
                "{}impl Into<{}Enum> for {} {{",
                indent,
                enum_entry["name"].as_str().unwrap(),
                enum_entry["name"].as_str().unwrap()
            )
            .unwrap();
            let indent = "        ";
            writeln!(
                out,
                "{}fn into(self) -> {}Enum {{",
                indent,
                enum_entry["name"].as_str().unwrap(),
            );
            let indent = "            ";
            writeln!(out, "{}match self.0 {{", indent);

            let indent = "                ";

            let mut default_member = None;
            for c in enum_entry["members"].as_array().unwrap() {
                writeln!(
                    out,
                    "{}{} => {}Enum::{},",
                    indent,
                    c["discriminant"].as_str().unwrap(),
                    enum_entry["name"].as_str().unwrap(),
                    c["name"].as_str().unwrap()
                );
                if let Some(is_default_str) = c["default"].as_str() {
                    if is_default_str == "true" {
                        default_member = Some(c["name"].as_str().unwrap())
                    }
                }
            }

            if let Some(default_member_name) = default_member {
                writeln!(
                    out,
                    "{}_ => {}Enum::{},",
                    indent,
                    enum_entry["name"].as_str().unwrap(),
                    default_member_name
                );
            }

            let indent = "            ";
            writeln!(out, "{}}}", indent);
            let indent = "        ";
            writeln!(out, "{}}}", indent);
            let indent = "    ";
            writeln!(out, "{}}}", indent);
            writeln!(out);

            // Members are named in the schema as PascalCase variants (NoValue,
            // Attribute, ...), which is the right reading for an enum but trips
            // non_upper_case_globals once emitted as associated consts. The
            // naming is a schema decision, so silence the lint rather than
            // rewriting the API surface.
            writeln!(out, "{}#[allow(non_upper_case_globals)]", indent);
            writeln!(
                out,
                "{}impl {} {{",
                indent,
                enum_entry["name"].as_str().unwrap(),
            );
            let indent = "        ";
            for c in enum_entry["members"].as_array().unwrap() {
                writeln!(
                    out,
                    "{}pub const {}: {} = {};",
                    indent,
                    c["name"].as_str().unwrap(),
                    enum_entry["repr_type"].as_str().unwrap(),
                    c["discriminant"].as_str().unwrap()
                );
            }
            let indent = "    ";
            writeln!(out, "{}}}", indent);
            writeln!(out);
        }
    }
}

fn generate_structs(
    out: &mut File,
    value: &serde_json::Value,
    namespace: &str,
    struct_names: &std::collections::HashSet<String>,
) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            if let Some(struct_description) = entry.get("description") {
                writeln!(
                    out,
                    "{}/// {}",
                    indent,
                    struct_description.as_str().unwrap()
                )
                .unwrap();
            }

            // derive(Clone) on a #[repr(C, packed)] struct clones by moving
            // each field out, because the derive refuses references to packed
            // fields. That move fails the moment a field is itself a non-Copy
            // struct -- exactly the shape of every result struct once key
            // material stopped being Copy. So for a non-Copy struct, Clone is
            // stripped from the derive list and emitted by hand below:
            // hand-written code may reference a packed field when its type has
            // alignment 1, which every generated struct does.
            let derives_str = entry["derives"].as_str();
            let is_copy = derives_str
                .map(|d| d.split(',').any(|x| x.trim() == "Copy"))
                .unwrap_or(false);
            let wants_clone = derives_str
                .map(|d| d.split(',').any(|x| x.trim() == "Clone"))
                .unwrap_or(false);
            let manual_clone = wants_clone && !is_copy;

            if let Some(derives) = derives_str {
                let emitted: Vec<&str> = derives
                    .split(',')
                    .map(str::trim)
                    .filter(|x| !(manual_clone && *x == "Clone"))
                    .collect();
                writeln!(out, "{}#[derive({})]", indent, emitted.join(", ")).unwrap();
            }

            writeln!(out, "{}#[repr(C, packed)]", indent).unwrap();

            writeln!(
                out,
                "{}pub struct {} {{",
                indent,
                entry["name"].as_str().unwrap()
            )
            .unwrap();

            if let Some(fields) = entry.get("fields") {
                if let Some(fields_arr) = fields.as_array() {
                    for field in fields_arr {
                        if let Some(field_description) = field.get("description") {
                            writeln!(
                                out,
                                "{}    /// {}",
                                indent,
                                field_description.as_str().unwrap()
                            )
                            .unwrap();
                        }
                        writeln!(
                            out,
                            "{}    pub {} : {},",
                            indent,
                            field["name"].as_str().unwrap(),
                            field["type"].as_str().unwrap()
                        )
                        .unwrap();
                    }
                }
            }
            writeln!(out, "    }}");

            if manual_clone {
                let name = entry["name"].as_str().unwrap();
                writeln!(out, "{}impl Clone for {} {{", indent, name).unwrap();
                writeln!(out, "{}    fn clone(&self) -> Self {{", indent).unwrap();
                writeln!(out, "{}        Self {{", indent).unwrap();
                if let Some(fields_arr) = entry.get("fields").and_then(|f| f.as_array()) {
                    for field in fields_arr {
                        let fname = field["name"].as_str().unwrap();
                        let ftype = field["type"].as_str().unwrap().trim();
                        // A nested schema struct may itself be non-Copy, so it
                        // must be cloned through a reference -- sound because
                        // packed structs have alignment 1. Everything else
                        // (primitives, byte arrays, enum newtypes) is Copy and
                        // is plain-copied, which sidesteps E0793 on the
                        // align > 1 primitives.
                        if struct_names.contains(ftype) {
                            writeln!(
                                out,
                                "{}            {}: self.{}.clone(),",
                                indent, fname, fname
                            )
                            .unwrap();
                        } else {
                            writeln!(out, "{}            {}: self.{},", indent, fname, fname)
                                .unwrap();
                        }
                    }
                }
                writeln!(out, "{}        }}", indent).unwrap();
                writeln!(out, "{}    }}", indent).unwrap();
                writeln!(out, "{}}}", indent).unwrap();
            }
        }
    }
}

fn generate_traits(out: &mut File, value: &serde_json::Value, namespace: &str) {
    let indent = "    ";
    if let Some(items) = value.as_array() {
        for entry in items {
            if let Some(struct_description) = entry.get("description") {
                writeln!(
                    out,
                    "{}/// {}",
                    indent,
                    struct_description.as_str().unwrap()
                )
                .unwrap();
            }

            writeln!(
                out,
                "{}pub trait {} {{",
                indent,
                entry["name"].as_str().unwrap()
            )
            .unwrap();

            if let Some(functions) = entry.get("functions") {
                if let Some(functions_arr) = functions.as_array() {
                    for function in functions_arr {
                        let mut instance_str = "".to_string();
                        let mut return_str = "".to_string();
                        let constraints = function.get("constraints").and_then(|v| v.as_str());

                        let param_str = match function["params"].as_array() {
                            Some(params) => params
                                .iter()
                                .filter(|p| {
                                    p["name"].as_str().unwrap_or("").is_empty()
                                        && p["type"].as_str().unwrap_or("").is_empty()
                                })
                                .count()
                                .eq(&params.len())
                                .then(|| String::new())
                                .unwrap_or_else(|| {
                                    params
                                        .iter()
                                        .filter(|p| !p["name"].as_str().unwrap_or("").is_empty())
                                        .map(|p| {
                                            format!(
                                                "{}: {}",
                                                p["name"].as_str().unwrap(),
                                                p["type"].as_str().unwrap()
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                }),
                            _ => "".to_string(),
                        };

                        let where_clause = constraints
                            .map(|c| format!(" where {c}"))
                            .unwrap_or_default();

                        if let Some(function_description) = function.get("description") {
                            writeln!(
                                out,
                                "{}    /// {}",
                                indent,
                                function_description.as_str().unwrap()
                            )
                            .unwrap();
                        }

                        // Emit param descriptions as doc comment lines
                        if let Some(params) = function["params"].as_array() {
                            for p in params {
                                if let Some(pdesc) = p.get("description") {
                                    writeln!(
                                        out,
                                        "{}    /// * `{}` - {}",
                                        indent,
                                        p["name"].as_str().unwrap(),
                                        pdesc.as_str().unwrap()
                                    )
                                    .unwrap();
                                }
                            }
                        }

                        if let Some(instance) = function.get("instance") {
                            instance_str = format!("{}, ", instance.as_str().unwrap());
                        }

                        // A fallible function returns Result over the wire
                        // status enum. Infallible functions keep their bare
                        // return: the status prefix is uniform on the wire,
                        // but only a function that can actually fail should
                        // force callers through a Result.
                        let fallible = function
                            .get("fallible")
                            .and_then(|f| f.as_str())
                            .map(|f| f == "true")
                            .unwrap_or(false);
                        if let Some(return_val) = function.get("return") {
                            let ret = return_val.as_str().unwrap();
                            return_str = if fallible {
                                format!(" -> Result<{}, StatusCode>", ret)
                            } else {
                                format!(" -> {}", ret)
                            };
                        } else if fallible {
                            return_str = " -> Result<(), StatusCode>".to_string();
                        }

                        writeln!(
                            out,
                            "{}    fn {}({}{}){}{};",
                            indent,
                            function["name"].as_str().unwrap(),
                            instance_str,
                            param_str,
                            return_str,
                            where_clause
                        );
                    }
                }
            }
            writeln!(out, "    }}");
        }
    }
}

fn generate_api(parsed: &serde_json::Value, outfile: PathBuf) {
    let mut out =
        fs::File::create(&outfile).expect(format!("failed to create {:?}", outfile).as_str());

    // Struct names across every namespace, so the manual Clone emission can
    // tell a nested (possibly non-Copy) struct field from a Copy one.
    let mut struct_names = std::collections::HashSet::new();
    if let Some(api) = parsed.as_object() {
        for value in api.values() {
            if let Some(structs) = value.get("structs").and_then(|s| s.as_array()) {
                for entry in structs {
                    if let Some(name) = entry["name"].as_str() {
                        struct_names.insert(name.to_string());
                    }
                }
            }
        }
    }

    if let Some(api) = parsed.as_object() {
        for namespace in api.keys() {
            let value = api.get(namespace).unwrap();
            writeln!(out, "pub mod {} {{", namespace).unwrap();
            writeln!(out, "    #[allow(unused)]").unwrap();
            writeln!(out, "    use super::*;").unwrap();

            if let Some(enums) = value.get("enums") {
                generate_enums(&mut out, enums, namespace);
            } else {
                writeln!(out, "    // (no enums in {}!)", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(sz_consts) = value.get("sz_consts") {
                generate_sz_consts(&mut out, sz_consts, namespace);
            } else {
                writeln!(out, "    // (no sz_consts in {}!)", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(byte_aliases) = value.get("byte_aliases") {
                generate_byte_aliases(&mut out, byte_aliases, namespace);
            } else {
                writeln!(out, "    // (no byte_aliases in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(empty_consts) = value.get("empty_consts") {
                generate_empty_consts(&mut out, empty_consts, namespace);
            } else {
                writeln!(out, "    // (no empty_consts in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(structs) = value.get("structs") {
                generate_structs(&mut out, structs, namespace, &struct_names);
            } else {
                writeln!(out, "    // (no structs in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(traits) = value.get("traits") {
                generate_traits(&mut out, traits, namespace);
            } else {
                writeln!(out, "    // (no traits in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(functions) = value.get("functions") {
                generate_functions(&mut out, functions, namespace);
            } else {
                writeln!(out, "    // (no functions in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();

            writeln!(out, "}}");
            writeln!(out).unwrap();
            writeln!(out, "#[allow(unused)]").unwrap();
            writeln!(out, "use {}::*;", namespace).unwrap();
            writeln!(out);
        }
    }
}

// ---------------------------------------------------------------------------
// Doc merge — a port of doc/merge_docs.jq.
//
// config/api_core.json is the source of truth; doc/api_core_docs.json overlays
// descriptions onto it. Entries are matched by "name" at every level; a source
// entry with no matching doc entry passes through untouched, and a doc entry
// with no matching source entry is ignored. Doc values win on key collisions,
// but a doc array never replaces a source array wholesale — nested arrays
// (enum members, struct fields, trait functions, function params) are merged
// by name in the same way.
//
// serde_json is built with "preserve_order", so key insertion order survives
// and Map::insert keeps an existing key in place — matching jq's `+` operator.
// ---------------------------------------------------------------------------

fn doc_for<'a>(
    overlay: Option<&'a serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    overlay?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name").and_then(|n| n.as_str()) == Some(name))
}

fn entry_name(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("name")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
}

/// Copy every key of `doc` onto `item`, except those named in `skip`.
fn overlay_fields(item: &mut serde_json::Value, doc: &serde_json::Value, skip: &[&str]) {
    let (Some(target), Some(source)) = (item.as_object_mut(), doc.as_object()) else {
        return;
    };
    for (key, value) in source {
        if skip.contains(&key.as_str()) {
            continue;
        }
        target.insert(key.clone(), value.clone());
    }
}

/// Merge a flat array of named objects.
fn merge_by_name(base: &mut serde_json::Value, overlay: Option<&serde_json::Value>) {
    let Some(items) = base.as_array_mut() else {
        return;
    };
    for item in items.iter_mut() {
        let Some(name) = entry_name(item) else {
            continue;
        };
        if let Some(doc) = doc_for(overlay, &name).cloned() {
            overlay_fields(item, &doc, &[]);
        }
    }
}

/// Merge an array of named objects that each contain a nested named array
/// (`members` for enums, `fields` for structs, `params` for functions).
fn merge_nested(base: &mut serde_json::Value, overlay: Option<&serde_json::Value>, nested: &str) {
    let Some(items) = base.as_array_mut() else {
        return;
    };
    for item in items.iter_mut() {
        let Some(name) = entry_name(item) else {
            continue;
        };
        let Some(doc) = doc_for(overlay, &name).cloned() else {
            continue;
        };
        overlay_fields(item, &doc, &[nested]);
        if let (Some(inner), Some(doc_inner)) = (item.get_mut(nested), doc.get(nested)) {
            merge_by_name(inner, Some(doc_inner));
        }
    }
}

/// Traits nest one level deeper: trait -> functions -> params.
fn merge_traits(base: &mut serde_json::Value, overlay: Option<&serde_json::Value>) {
    let Some(items) = base.as_array_mut() else {
        return;
    };
    for item in items.iter_mut() {
        let Some(name) = entry_name(item) else {
            continue;
        };
        let Some(doc) = doc_for(overlay, &name).cloned() else {
            continue;
        };
        overlay_fields(item, &doc, &["functions"]);
        if let (Some(functions), Some(doc_functions)) =
            (item.get_mut("functions"), doc.get("functions"))
        {
            merge_nested(functions, Some(doc_functions), "params");
        }
    }
}

fn merge_module(src: &mut serde_json::Value, doc: &serde_json::Value) {
    for key in ["sz_consts", "byte_aliases", "empty_consts"] {
        if let Some(base) = src.get_mut(key) {
            merge_by_name(base, doc.get(key));
        }
    }
    if let Some(base) = src.get_mut("enums") {
        merge_nested(base, doc.get("enums"), "members");
    }
    if let Some(base) = src.get_mut("structs") {
        merge_nested(base, doc.get("structs"), "fields");
    }
    if let Some(base) = src.get_mut("traits") {
        merge_traits(base, doc.get("traits"));
    }
    if let Some(base) = src.get_mut("functions") {
        merge_nested(base, doc.get("functions"), "params");
    }
    // "impls" is carried through from the source unchanged.
}

fn merge_docs(mut src: serde_json::Value, docs: &serde_json::Value) -> serde_json::Value {
    let empty = serde_json::Value::Object(Default::default());
    if let Some(modules) = src.as_object_mut() {
        for (namespace, module) in modules.iter_mut() {
            let doc_module = docs.get(namespace.as_str()).unwrap_or(&empty);
            merge_module(module, doc_module);
        }
    }
    src
}

fn read_json(path: &str) -> serde_json::Value {
    let raw = fs::read_to_string(path).expect(format!("failed to read {}", path).as_str());
    serde_json::from_str(&raw).expect(format!("failed to parse {}", path).as_str())
}

fn main() {
    const SRC: &str = "config/api_core.json";
    const DOCS: &str = "doc/api_core_docs.json";
    const MERGED: &str = ".generated/api_core_merged.json";

    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed={}", DOCS);

    let merged = merge_docs(read_json(SRC), &read_json(DOCS));

    // The Python and TypeScript generators read the merged schema from disk, so
    // keep writing it. Emitting it here means there is exactly one implementation
    // of the merge and no separate `make merge_docs` step to forget.
    fs::create_dir_all(".generated").expect("failed to create .generated");
    fs::write(
        MERGED,
        serde_json::to_string_pretty(&merged).expect("failed to serialize merged schema"),
    )
    .expect("failed to write merged schema");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("api_core.rs");
    generate_api(&merged, out_path);
}
