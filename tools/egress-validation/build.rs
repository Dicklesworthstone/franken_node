use quote::ToTokens;
use std::{env, fs, path::Path};
use syn::{Item, Type};

fn parse(path: &Path) -> syn::File {
    println!("cargo:rerun-if-changed={}", path.display());
    syn::parse_file(&fs::read_to_string(path).expect("read production source"))
        .expect("parse production source")
}

fn module(root: &Path, name: &str, relative: &str) -> String {
    let path = root.join(relative).canonicalize().expect("production module exists");
    println!("cargo:rerun-if-changed={}", path.display());
    format!("#[path = {:?}] pub mod {name};\n", path.to_str().expect("UTF-8 source path"))
}

fn main() {
    let manifest = env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory");
    let root = Path::new(&manifest).join("../../crates/franken-node/src");
    let config = parse(&root.join("config.rs"));
    let mut declarations = String::from("pub mod config { use serde::{Deserialize, Serialize};\n");
    let mut selected = 0;
    for item in config.items {
        let keep = match &item {
            Item::Enum(item) => item.ident == "SsrfEnforcementMode",
            Item::Struct(item) => item.ident == "NetworkPolicyConfig" || item.ident == "NetworkAllowlistEntry",
            Item::Fn(item) => item.sig.ident == "default_true",
            Item::Impl(item) => {
                matches!(item.self_ty.as_ref(), Type::Path(ty) if ty.path.is_ident("NetworkPolicyConfig"))
                    && item.trait_.as_ref().is_some_and(|(_, path, _)| path.is_ident("Default"))
            }
            _ => false,
        };
        if keep {
            selected += 1;
            declarations.push_str(&item.into_token_stream().to_string());
            declarations.push('\n');
        }
    }
    assert_eq!(selected, 5, "production network config inventory changed");
    declarations.push_str("}\n");
    let mut helpers = 0;
    for item in parse(&root.join("lib.rs")).items {
        if matches!(&item, Item::Fn(item) if item.sig.ident == "push_bounded") {
            helpers += 1;
            declarations.push_str(&item.into_token_stream().to_string());
            declarations.push('\n');
        }
    }
    assert_eq!(helpers, 1, "production bounded helper missing");
    declarations.push_str(&module(&root, "capacity_defaults", "capacity_defaults.rs"));
    declarations.push_str("pub mod security {\n");
    for name in ["constant_time", "cuckoo_filter", "remote_cap", "network_guard", "lineage_tracker", "ssrf_policy"] {
        declarations.push_str(&module(&root, name, &format!("security/{name}.rs")));
    }
    declarations.push_str("}\npub mod ops {\n");
    for name in ["ssrf_gated_host_io", "flow_gated_host_io"] {
        declarations.push_str(&module(&root, name, &format!("ops/{name}.rs")));
    }
    declarations.push_str("}\n");
    println!("cargo:rerun-if-changed={}", root.join("security/ssrf_policy/ipv6.rs").display());
    let out = env::var_os("OUT_DIR").expect("Cargo output directory");
    fs::write(Path::new(&out).join("production_egress.rs"), declarations).expect("write compile harness");
