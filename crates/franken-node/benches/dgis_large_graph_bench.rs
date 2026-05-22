use std::time::Duration;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::dgis::contagion_graph::{ContagionGraph, NodeId};
use frankenengine_node::dgis::contagion_simulator::{InfectionState, SimulatorConfig, step};

#[derive(Debug, Clone, Copy)]
struct LargeGraphCase {
    requested_nodes: usize,
    steps: usize,
    edge_density: f64,
    seed: u64,
}

#[derive(Debug)]
struct LargeGraphInput {
    requested_nodes: usize,
    actual_nodes: usize,
    edge_count: usize,
    steps: usize,
    graph: ContagionGraph,
    initial_infected: Vec<NodeId>,
    config: SimulatorConfig,
}

const CASES: &[LargeGraphCase] = &[
    LargeGraphCase {
        requested_nodes: 1_000,
        steps: 100,
        edge_density: 0.001,
        seed: 0xD615_0001,
    },
    LargeGraphCase {
        requested_nodes: 10_000,
        steps: 100,
        edge_density: 0.0001,
        seed: 0xD615_0010,
    },
    LargeGraphCase {
        requested_nodes: 50_000,
        steps: 50,
        edge_density: 0.00005,
        seed: 0xD615_0050,
    },
    LargeGraphCase {
        requested_nodes: 1_024,
        steps: 100,
        edge_density: 0.01,
        seed: 0xD615_1024,
    },
];

fn build_input(case: LargeGraphCase) -> LargeGraphInput {
    let graph = ContagionGraph::generate_sparse_deterministic_for_benchmark(
        case.seed,
        case.requested_nodes,
        case.edge_density,
    );
    let actual_nodes = graph.nodes().len();
    let edge_count = graph.edge_count();
    let seed_count = actual_nodes.saturating_div(100).max(1);
    let initial_infected = graph.nodes().iter().take(seed_count).cloned().collect();
    let config = SimulatorConfig {
        max_steps: u32::try_from(case.steps).unwrap_or(u32::MAX),
        infection_threshold: 1.0,
        decay_factor: 1.0,
        seed: case.seed,
    };

    LargeGraphInput {
        requested_nodes: case.requested_nodes,
        actual_nodes,
        edge_count,
        steps: case.steps,
        graph,
        initial_infected,
        config,
    }
}

fn benchmark_id(input: &LargeGraphInput) -> String {
    format!(
        "requested_{}n_actual_{}n_{}e_{}s",
        input.requested_nodes, input.actual_nodes, input.edge_count, input.steps
    )
}

fn run_step_loop(input: &LargeGraphInput) -> usize {
    let mut state = InfectionState::new(&input.initial_infected);
    for _ in 0..input.steps {
        let Ok(next) = step(&input.graph, &state, &input.config) else {
            return usize::MAX;
        };
        state = next;
    }
    state.infected_count()
}

fn bench_step_loop(c: &mut Criterion) {
    let inputs: Vec<LargeGraphInput> = CASES.iter().copied().map(build_input).collect();
    let mut group = c.benchmark_group("dgis_large_graph");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    for input in &inputs {
        group.bench_with_input(
            BenchmarkId::new("step_loop", benchmark_id(input)),
            input,
            |b, input| {
                b.iter(|| black_box(run_step_loop(black_box(input))));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_step_loop);
criterion_main!(benches);
