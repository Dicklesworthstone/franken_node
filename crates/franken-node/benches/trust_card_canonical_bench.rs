//! Benchmark for trust card canonical encoding optimization.
//!
//! Profiles the hotspot in canonical JSON encoding to measure:
//! - BTreeSet allocation overhead for key sorting
//! - Recursive clone overhead in value canonicalization
//! - JSON serialization performance with large nested objects

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::connector::canonical_serializer::{
    CanonicalSchema, CanonicalSerializer, TrustObjectType,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::io::Write;

/// Current implementation - creates BTreeSet and clones keys
fn canonicalize_value_current(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: BTreeSet<String> = BTreeSet::new();
            for key in map.keys() {
                keys.insert(key.clone());
            }
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_current(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_value_current).collect())
        }
        _ => value,
    }
}

/// Optimized implementation - avoids BTreeSet allocation and reduces cloning
fn canonicalize_value_optimized(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable(); // In-place sort, no BTreeSet allocation

            let mut out = Map::with_capacity(keys.len()); // Pre-allocate capacity
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_optimized(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(canonicalize_value_optimized)
                .collect(),
        ),
        _ => value,
    }
}

/// Generate nested JSON object for benchmarking
fn generate_nested_trust_card(depth: usize, width: usize) -> Value {
    fn build_object(current_depth: usize, max_depth: usize, width: usize) -> Value {
        let mut map = Map::new();

        for i in 0..width {
            let key = format!("field_{:03}", i);
            let value = if current_depth < max_depth {
                build_object(current_depth + 1, max_depth, width)
            } else {
                serde_json::json!({
                    "extension_id": format!("npm:@acme/plugin-{}", i),
                    "version": "1.0.0",
                    "hash": format!("{:064x}", i),
                    "timestamp": "2026-04-22T10:00:00Z",
                    "metadata": {
                        "size": 12345 + i,
                        "dependencies": (0..i%5).map(|j| format!("dep-{}", j)).collect::<Vec<_>>(),
                    }
                })
            };
            map.insert(key, value);
        }

        Value::Object(map)
    }

    build_object(0, depth, width)
}

fn bench_canonical_encoding(c: &mut Criterion) {
    // Generate test data of various complexities
    let simple = generate_nested_trust_card(1, 5);
    let medium = generate_nested_trust_card(3, 8);
    let complex = generate_nested_trust_card(4, 12);

    let test_cases = vec![
        ("simple_1x5", simple),
        ("medium_3x8", medium),
        ("complex_4x12", complex),
    ];

    let mut group = c.benchmark_group("trust_card_canonical");

    for (name, data) in &test_cases {
        // Baseline: current implementation
        group.bench_with_input(BenchmarkId::new("current", name), data, |b, data| {
            b.iter(|| black_box(canonicalize_value_current(black_box(data.clone()))))
        });

        // Optimized: reduced allocation
        group.bench_with_input(BenchmarkId::new("optimized", name), data, |b, data| {
            b.iter(|| black_box(canonicalize_value_optimized(black_box(data.clone()))))
        });

        // Additional optimization: test serialization too
        group.bench_with_input(
            BenchmarkId::new("serialize_current", name),
            data,
            |b, data| {
                b.iter(|| {
                    let canonical = canonicalize_value_current(data.clone());
                    black_box(serde_json::to_string(&canonical).unwrap())
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("serialize_optimized", name),
            data,
            |b, data| {
                b.iter(|| {
                    let canonical = canonicalize_value_optimized(data.clone());
                    black_box(serde_json::to_string(&canonical).unwrap())
                })
            },
        );
    }

    group.finish();
}

fn sample_connector_payload(schema: &CanonicalSchema) -> Value {
    let mut map = Map::with_capacity(schema.field_order.len());
    for (index, field) in schema.field_order.iter().enumerate() {
        let value = match index % 4 {
            0 => serde_json::json!({
                "owner": format!("ops-team-{index:02}"),
                "tags": [
                    format!("tag-{index:02}"),
                    format!("tag-{:02}-with-escapes-\\n-\\t-\\\"", index),
                    format!("tag-{:02}-unicode-cafe-{}", index, '\u{00E9}'),
                ],
                "limits": {
                    "max_events": 1024 + index,
                    "window_secs": 3600 + index,
                }
            }),
            1 => Value::Array(
                (0..6)
                    .map(|item| {
                        serde_json::json!({
                            "id": format!("{field}-{index}-{item}"),
                            "path": format!("/var/lib/franken/{field}/{item}"),
                            "enabled": item % 2 == 0,
                        })
                    })
                    .collect(),
            ),
            2 => Value::String(format!(
                "canonical-{}-{:02}-line1\\nline2\\tquote-\\\"slash-\\\\",
                field, index
            )),
            _ => Value::Number(serde_json::Number::from(10_000 + index as u64)),
        };
        map.insert(field.clone(), value);
    }
    Value::Object(map)
}

fn encode_string_alloc(out: &mut Vec<u8>, value: &str) {
    let encoded = serde_json::to_string(value).expect("string encoding should succeed");
    out.extend_from_slice(encoded.as_bytes());
}

fn encode_string_direct(out: &mut Vec<u8>, value: &str) {
    serde_json::to_writer(out, value).expect("direct string encoding should succeed");
}

fn write_value_current_like(
    out: &mut Vec<u8>,
    value: &Value,
    field_path: &str,
    no_float: bool,
) -> Result<(), ()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else if no_float {
                return Err(());
            } else {
                return Err(());
            }
        }
        Value::String(value) => encode_string_alloc(out, value),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                let child_path = format!("{field_path}[{index}]");
                write_value_current_like(out, item, &child_path, no_float)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, nested_value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode_string_alloc(out, key);
                out.push(b':');
                let child_path = format!("{field_path}.{key}");
                write_value_current_like(out, nested_value, &child_path, no_float)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_value_no_path_alloc(out: &mut Vec<u8>, value: &Value, no_float: bool) -> Result<(), ()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                out.extend_from_slice(value.to_string().as_bytes());
            } else if no_float {
                return Err(());
            } else {
                return Err(());
            }
        }
        Value::String(value) => encode_string_alloc(out, value),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value_no_path_alloc(out, item, no_float)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, nested_value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode_string_alloc(out, key);
                out.push(b':');
                write_value_no_path_alloc(out, nested_value, no_float)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_value_direct_string(out: &mut Vec<u8>, value: &Value, no_float: bool) -> Result<(), ()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                write!(out, "{value}").expect("int encoding should succeed");
            } else if let Some(value) = number.as_u64() {
                write!(out, "{value}").expect("uint encoding should succeed");
            } else if no_float {
                return Err(());
            } else {
                return Err(());
            }
        }
        Value::String(value) => encode_string_direct(out, value),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value_direct_string(out, item, no_float)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, nested_value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                encode_string_direct(out, key);
                out.push(b':');
                write_value_direct_string(out, nested_value, no_float)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn encode_current_like(schema: &CanonicalSchema, value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .expect("schema payload should be an object");
    let mut canonical = Vec::new();
    canonical.push(b'{');
    for (index, field) in schema.field_order.iter().enumerate() {
        if index > 0 {
            canonical.push(b',');
        }
        encode_string_alloc(&mut canonical, field);
        canonical.push(b':');
        let field_value = object
            .get(field)
            .expect("schema field should exist in sample payload");
        write_value_current_like(&mut canonical, field_value, field, schema.no_float)
            .expect("benchmark payload should be canonical");
    }
    canonical.push(b'}');
    length_prefix(canonical)
}

fn encode_no_path_alloc(schema: &CanonicalSchema, value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .expect("schema payload should be an object");
    let mut canonical = Vec::new();
    canonical.push(b'{');
    for (index, field) in schema.field_order.iter().enumerate() {
        if index > 0 {
            canonical.push(b',');
        }
        encode_string_alloc(&mut canonical, field);
        canonical.push(b':');
        let field_value = object
            .get(field)
            .expect("schema field should exist in sample payload");
        write_value_no_path_alloc(&mut canonical, field_value, schema.no_float)
            .expect("benchmark payload should be canonical");
    }
    canonical.push(b'}');
    length_prefix(canonical)
}

fn encode_direct_string(schema: &CanonicalSchema, value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .expect("schema payload should be an object");
    let mut canonical = Vec::new();
    canonical.push(b'{');
    for (index, field) in schema.field_order.iter().enumerate() {
        if index > 0 {
            canonical.push(b',');
        }
        encode_string_direct(&mut canonical, field);
        canonical.push(b':');
        let field_value = object
            .get(field)
            .expect("schema field should exist in sample payload");
        write_value_direct_string(&mut canonical, field_value, schema.no_float)
            .expect("benchmark payload should be canonical");
    }
    canonical.push(b'}');
    length_prefix(canonical)
}

fn length_prefix(payload: Vec<u8>) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("benchmark payload should fit in u32");
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(&payload);
    encoded
}

fn bench_connector_canonical_serializer(c: &mut Criterion) {
    let object_type = TrustObjectType::PolicyCheckpoint;
    let serializer = CanonicalSerializer::with_all_schemas();
    let schema = serializer
        .get_schema(object_type)
        .expect("policy checkpoint schema should exist")
        .clone();
    let payload = sample_connector_payload(&schema);

    let mut validation_serializer = CanonicalSerializer::with_all_schemas();
    let actual = validation_serializer
        .serialize_value(object_type, &payload, "bench-validate")
        .expect("current serializer should encode payload");
    assert_eq!(actual, encode_current_like(&schema, &payload));
    assert_eq!(actual, encode_no_path_alloc(&schema, &payload));
    assert_eq!(actual, encode_direct_string(&schema, &payload));

    let mut group = c.benchmark_group("connector_canonical_serializer");

    group.bench_function("serialize_value_current", |b| {
        b.iter(|| {
            let mut serializer = CanonicalSerializer::with_all_schemas();
            black_box(
                serializer
                    .serialize_value(object_type, black_box(&payload), "bench-current")
                    .expect("serialize_value should succeed"),
            )
        })
    });

    group.bench_function("encode_current_like", |b| {
        b.iter(|| black_box(encode_current_like(&schema, black_box(&payload))))
    });

    group.bench_function("encode_no_path_alloc", |b| {
        b.iter(|| black_box(encode_no_path_alloc(&schema, black_box(&payload))))
    });

    group.bench_function("encode_direct_string", |b| {
        b.iter(|| black_box(encode_direct_string(&schema, black_box(&payload))))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_canonical_encoding,
    bench_connector_canonical_serializer
);
criterion_main!(benches);
