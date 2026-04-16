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
            writeln!(
                out,
                "{}pub type {} = [u8; {}];",
                indent,
                entry["name"].as_str().unwrap(),
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

    if let Some(enums) = value.as_object() {
        for key in enums.keys() {
            writeln!(out);
            let enum_entry = enums.get(key).unwrap();
            writeln!(out, "    #[repr({})]", enum_entry["repr_type"]).unwrap();
            writeln!(out, "    pub enum {} {{", key).unwrap();
            writeln!(out);

            for c in enum_entry["members"].as_array().unwrap() {
                writeln!(out, "        /// {},", c["description"].as_str().unwrap());
                writeln!(
                    out,
                    "        {} = {},",
                    c["name"].as_str().unwrap(),
                    c["discriminant"].as_str().unwrap()
                )
                .unwrap();
            }
            writeln!(out);
            writeln!(out, "    }}");
        }
    }
}

fn generate_structs(out: &mut File, value: &serde_json::Value, namespace: &str) {
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

            if let Some(derives) = entry["derives"].as_str() {
                writeln!(out, "{}#[derive({})]", indent, derives).unwrap();
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
                                    ).unwrap();
                                }
                            }
                        }

                        if let Some(instance) = function.get("instance") {
                            instance_str = format!("{}, ", instance.as_str().unwrap());
                        }

                        if let Some(return_val) = function.get("return") {
                            return_str = format!(" -> {}", return_val.as_str().unwrap());
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

fn generate_api(jsonfile: &str, outfile: PathBuf) {
    let mut out =
        fs::File::create(&outfile).expect(format!("failed to create {:?}", outfile).as_str());
    let raw = fs::read_to_string(&jsonfile).expect(format!("failed to read {}", jsonfile).as_str());
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect(format!("failed to parse {}", jsonfile).as_str());

    if let Some(api) = parsed.as_object() {
        for namespace in api.keys() {
            let value = api.get(namespace).unwrap();
            writeln!(out, "pub mod {} {{", namespace).unwrap();
            writeln!(out, "    #[allow(unused)]").unwrap();
            writeln!(out, "    use super::*;").unwrap();

            if let Some(enums) = value.get("enums") {
                generate_enums(&mut out, enums, namespace);
            } else {
                writeln!(out, "    // (no enums in {})", namespace).unwrap();
            }
            writeln!(out).unwrap();
            if let Some(sz_consts) = value.get("sz_consts") {
                generate_sz_consts(&mut out, sz_consts, namespace);
            } else {
                writeln!(out, "    // (no sz_consts in {})", namespace).unwrap();
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
                generate_structs(&mut out, structs, namespace);
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

fn main() {
    println!("cargo:rerun-if-changed=.generated/api_core_merged.json");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("api_core.rs");
    generate_api(".generated/api_core_merged.json", out_path);
}
