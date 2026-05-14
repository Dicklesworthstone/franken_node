//! Top-level DGIS (Dependency Graph Immune System) module.
//!
//! This module hosts the deterministic graph ingestion pipeline and downstream
//! contagion-analysis utilities. The sibling `crate::security::dgis` module
//! contains the older barrier-primitives + update-copilot subsystems; that
//! split is preserved so the two surface areas evolve independently.
//!
//! See bd-2bj4 (graph ingestion) and bd-1q38 (contagion simulator) for the
//! sub-task plans that populate this module.
//!
//! `fragility_model` (bd-2jns.1 sub-task 1) contributes the
//! maintainer/publisher fragility type foundation used by the SPOF detector.

pub mod contagion_graph;
pub mod contagion_profiles;
pub mod contagion_simulator;
pub mod fragility_fixtures;
pub mod fragility_model;
pub mod graph_ingestion;
pub mod graph_seeds;
pub mod spof_detection;
