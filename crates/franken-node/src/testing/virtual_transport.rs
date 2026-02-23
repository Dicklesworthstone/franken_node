//! bd-2ko: Virtual Transport Layer for deterministic lab runtime (Section 10.11).
//!
//! Product-layer virtual transport integration that bridges the canonical 10.14
//! virtual transport fault harness into the testing module. Provides a
//! deterministic, seed-based transport simulation layer with configurable fault
//! injection (drops, reordering, corruption, partitions) for multi-node
//! distributed protocol testing.
//!
//! Schema version: vt-v1.0

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "vt-v1.0";
pub const BEAD_ID: &str = "bd-2ko";
pub const SECTION: &str = "10.11";

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Message successfully sent through the transport layer.
    pub const VT_001: &str = "VT-001";
    /// Message dropped due to fault injection.
    pub const VT_002: &str = "VT-002";
    /// Message reordered in the delivery buffer.
    pub const VT_003: &str = "VT-003";
    /// Message payload corrupted (bit flips applied).
    pub const VT_004: &str = "VT-004";
    /// Network partition activated on a link.
    pub const VT_005: &str = "VT-005";
    /// Network partition healed on a link.
    pub const VT_006: &str = "VT-006";
    /// New transport link created.
    pub const VT_007: &str = "VT-007";
    /// Transport link destroyed.
    pub const VT_008: &str = "VT-008";
}

// ── Error codes ──────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Attempted to create a link with an ID that already exists.
    pub const ERR_VT_LINK_EXISTS: &str = "ERR_VT_LINK_EXISTS";
    /// Referenced link ID does not exist in the transport layer.
    pub const ERR_VT_LINK_NOT_FOUND: &str = "ERR_VT_LINK_NOT_FOUND";
    /// Drop probability is outside the valid range [0.0, 1.0].
    pub const ERR_VT_INVALID_PROBABILITY: &str = "ERR_VT_INVALID_PROBABILITY";
    /// Link is partitioned; message delivery is blocked.
    pub const ERR_VT_PARTITIONED: &str = "ERR_VT_PARTITIONED";
}

// ── Invariants ───────────────────────────────────────────────────────────────

pub mod invariants {
    /// Same seed produces identical message sequences and fault outcomes.
    pub const INV_VT_DETERMINISTIC: &str = "INV-VT-DETERMINISTIC";
    /// Messages within a non-reordered link are delivered in FIFO order.
    pub const INV_VT_DELIVERY_ORDER: &str = "INV-VT-DELIVERY-ORDER";
    /// Observed drop rate converges to the configured probability.
    pub const INV_VT_DROP_RATE: &str = "INV-VT-DROP-RATE";
    /// Corruption applies exactly the configured number of bit flips.
    pub const INV_VT_CORRUPT_BITS: &str = "INV-VT-CORRUPT-BITS";
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Configuration for link-level fault injection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkFaultConfig {
    /// Probability that a message is silently dropped. Range: [0.0, 1.0].
    pub drop_probability: f64,
    /// Maximum depth for reorder buffer. 0 means no reordering.
    pub reorder_depth: usize,
    /// Number of bits to flip per corrupted message. 0 means no corruption.
    pub corrupt_bit_count: usize,
    /// Fixed delay in ticks before a message is delivered.
    pub delay_ticks: u64,
    /// Whether the link is fully partitioned (no messages pass).
    pub partition: bool,
}

impl Default for LinkFaultConfig {
    fn default() -> Self {
        Self {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 0,
            delay_ticks: 0,
            partition: false,
        }
    }
}

impl LinkFaultConfig {
    /// Create a fault-free configuration.
    pub fn no_faults() -> Self {
        Self::default()
    }

    /// Validate configuration constraints.
    pub fn validate(&self) -> Result<(), VirtualTransportError> {
        if !(0.0..=1.0).contains(&self.drop_probability) {
            return Err(VirtualTransportError::InvalidProbability {
                field: "drop_probability".to_string(),
                value: self.drop_probability,
            });
        }
        Ok(())
    }
}

/// A message in transit through the virtual transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier.
    pub id: u64,
    /// Source node identifier.
    pub source: String,
    /// Target node identifier.
    pub target: String,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Tick at which the message was created/sent.
    pub tick_created: u64,
    /// Tick at which the message was delivered (None if not yet delivered).
    pub tick_delivered: Option<u64>,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Message(id={}, {}->{}; {} bytes, tick={})",
            self.id,
            self.source,
            self.target,
            self.payload.len(),
            self.tick_created
        )
    }
}

/// State of a single transport link between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkState {
    /// Source node identifier.
    pub source: String,
    /// Target node identifier.
    pub target: String,
    /// Fault injection configuration for this link.
    pub config: LinkFaultConfig,
    /// Buffered messages awaiting delivery.
    pub buffer: Vec<Message>,
    /// Whether the link is currently active.
    pub active: bool,
}

impl LinkState {
    /// Create a new active link with the given fault configuration.
    pub fn new(source: String, target: String, config: LinkFaultConfig) -> Self {
        Self {
            source,
            target,
            config,
            buffer: Vec::new(),
            active: true,
        }
    }

    /// Returns the canonical link identifier: "source->target".
    pub fn link_id(&self) -> String {
        format!("{}->{}", self.source, self.target)
    }
}

/// Events emitted by the virtual transport layer during simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportEvent {
    /// A message was successfully sent and enqueued.
    MessageSent {
        event_code: String,
        message_id: u64,
        link_id: String,
    },
    /// A message was dropped due to fault injection.
    MessageDropped {
        event_code: String,
        message_id: u64,
        link_id: String,
    },
    /// A message was reordered in the delivery buffer.
    MessageReordered {
        event_code: String,
        message_id: u64,
        link_id: String,
        new_position: usize,
    },
    /// A message payload was corrupted (bits flipped).
    MessageCorrupted {
        event_code: String,
        message_id: u64,
        link_id: String,
        bits_flipped: usize,
    },
    /// A partition was activated on a link.
    PartitionActivated { event_code: String, link_id: String },
    /// A partition was healed on a link.
    PartitionHealed { event_code: String, link_id: String },
}

impl TransportEvent {
    /// Return the event code string for this event.
    pub fn event_code(&self) -> &str {
        match self {
            TransportEvent::MessageSent { event_code, .. } => event_code,
            TransportEvent::MessageDropped { event_code, .. } => event_code,
            TransportEvent::MessageReordered { event_code, .. } => event_code,
            TransportEvent::MessageCorrupted { event_code, .. } => event_code,
            TransportEvent::PartitionActivated { event_code, .. } => event_code,
            TransportEvent::PartitionHealed { event_code, .. } => event_code,
        }
    }
}

/// Errors from the virtual transport layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VirtualTransportError {
    /// A link with the given ID already exists.
    LinkExists { link_id: String },
    /// No link found with the given ID.
    LinkNotFound { link_id: String },
    /// A probability value is outside [0.0, 1.0].
    InvalidProbability { field: String, value: f64 },
    /// The link is partitioned and cannot deliver messages.
    Partitioned { link_id: String },
}

impl fmt::Display for VirtualTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VirtualTransportError::LinkExists { link_id } => {
                write!(f, "{}: {}", error_codes::ERR_VT_LINK_EXISTS, link_id)
            }
            VirtualTransportError::LinkNotFound { link_id } => {
                write!(f, "{}: {}", error_codes::ERR_VT_LINK_NOT_FOUND, link_id)
            }
            VirtualTransportError::InvalidProbability { field, value } => {
                write!(
                    f,
                    "{}: {}={}",
                    error_codes::ERR_VT_INVALID_PROBABILITY,
                    field,
                    value
                )
            }
            VirtualTransportError::Partitioned { link_id } => {
                write!(f, "{}: {}", error_codes::ERR_VT_PARTITIONED, link_id)
            }
        }
    }
}

/// Transport layer statistics snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    pub total_messages: u64,
    pub dropped_messages: u64,
    pub reordered_messages: u64,
    pub corrupted_messages: u64,
    pub delivered_messages: u64,
    pub active_links: usize,
    pub partitioned_links: usize,
}

// ── Simple deterministic PRNG ────────────────────────────────────────────────

/// Minimal xorshift64 PRNG for deterministic fault injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        // Ensure non-zero state.
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Return a float in [0.0, 1.0).
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }
}

// ── Core: VirtualTransportLayer ──────────────────────────────────────────────

/// The virtual transport layer simulates a network of links between nodes
/// with configurable, deterministic fault injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualTransportLayer {
    /// All links keyed by their canonical link_id ("source->target").
    pub links: BTreeMap<String, LinkState>,
    /// Seed used to initialize the deterministic PRNG.
    pub rng_seed: u64,
    /// Total messages sent through this transport layer.
    pub total_messages: u64,
    /// Total messages dropped by fault injection.
    pub dropped_messages: u64,
    /// Total messages reordered by fault injection.
    pub reordered_messages: u64,
    /// Total messages corrupted by fault injection.
    pub corrupted_messages: u64,
    /// Internal PRNG state for deterministic fault decisions.
    rng: Xorshift64,
    /// Next message ID to assign.
    next_message_id: u64,
    /// Current simulation tick.
    current_tick: u64,
    /// Accumulated event log.
    event_log: Vec<TransportEvent>,
}

impl VirtualTransportLayer {
    /// Create a new virtual transport layer with the given seed.
    pub fn new(rng_seed: u64) -> Self {
        Self {
            links: BTreeMap::new(),
            rng_seed,
            total_messages: 0,
            dropped_messages: 0,
            reordered_messages: 0,
            corrupted_messages: 0,
            rng: Xorshift64::new(rng_seed),
            next_message_id: 1,
            current_tick: 0,
            event_log: Vec::new(),
        }
    }

    /// Return the current simulation tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Advance the simulation clock by the given number of ticks.
    pub fn advance_tick(&mut self, ticks: u64) {
        self.current_tick = self.current_tick.saturating_add(ticks);
    }

    /// Access the full event log.
    pub fn event_log(&self) -> &[TransportEvent] {
        &self.event_log
    }

    /// Return a snapshot of transport statistics.
    pub fn stats(&self) -> TransportStats {
        let active_links = self
            .links
            .values()
            .filter(|l| l.active && !l.config.partition)
            .count();
        let partitioned_links = self.links.values().filter(|l| l.config.partition).count();
        let delivered = self.total_messages - self.dropped_messages;
        TransportStats {
            total_messages: self.total_messages,
            dropped_messages: self.dropped_messages,
            reordered_messages: self.reordered_messages,
            corrupted_messages: self.corrupted_messages,
            delivered_messages: delivered,
            active_links,
            partitioned_links,
        }
    }

    /// Create a new link between two nodes.
    pub fn create_link(
        &mut self,
        source: &str,
        target: &str,
        config: LinkFaultConfig,
    ) -> Result<String, VirtualTransportError> {
        config.validate()?;
        let link_id = format!("{}->{}", source, target);
        if self.links.contains_key(&link_id) {
            return Err(VirtualTransportError::LinkExists {
                link_id: link_id.clone(),
            });
        }
        let state = LinkState::new(source.to_string(), target.to_string(), config);
        self.links.insert(link_id.clone(), state);
        self.event_log.push(TransportEvent::MessageSent {
            event_code: event_codes::VT_007.to_string(),
            message_id: 0,
            link_id: link_id.clone(),
        });
        Ok(link_id)
    }

    /// Destroy a link, returning any buffered messages.
    pub fn destroy_link(&mut self, link_id: &str) -> Result<Vec<Message>, VirtualTransportError> {
        let state =
            self.links
                .remove(link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.to_string(),
                })?;
        self.event_log.push(TransportEvent::MessageSent {
            event_code: event_codes::VT_008.to_string(),
            message_id: 0,
            link_id: link_id.to_string(),
        });
        Ok(state.buffer)
    }

    /// Activate a partition on the given link.
    pub fn activate_partition(&mut self, link_id: &str) -> Result<(), VirtualTransportError> {
        let link =
            self.links
                .get_mut(link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.to_string(),
                })?;
        link.config.partition = true;
        self.event_log.push(TransportEvent::PartitionActivated {
            event_code: event_codes::VT_005.to_string(),
            link_id: link_id.to_string(),
        });
        Ok(())
    }

    /// Heal a partition on the given link.
    pub fn heal_partition(&mut self, link_id: &str) -> Result<(), VirtualTransportError> {
        let link =
            self.links
                .get_mut(link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.to_string(),
                })?;
        link.config.partition = false;
        self.event_log.push(TransportEvent::PartitionHealed {
            event_code: event_codes::VT_006.to_string(),
            link_id: link_id.to_string(),
        });
        Ok(())
    }

    /// Send a message through the transport layer.
    ///
    /// The message traverses the fault injection pipeline:
    /// 1. Partition check (immediate reject if partitioned).
    /// 2. Drop decision based on `drop_probability`.
    /// 3. Corruption based on `corrupt_bit_count`.
    /// 4. Reordering based on `reorder_depth`.
    /// 5. Enqueue into the link buffer.
    pub fn send_message(
        &mut self,
        source: &str,
        target: &str,
        payload: Vec<u8>,
    ) -> Result<u64, VirtualTransportError> {
        let link_id = format!("{}->{}", source, target);
        // Check link exists and is not partitioned.
        {
            let link =
                self.links
                    .get(&link_id)
                    .ok_or_else(|| VirtualTransportError::LinkNotFound {
                        link_id: link_id.clone(),
                    })?;
            if link.config.partition {
                return Err(VirtualTransportError::Partitioned {
                    link_id: link_id.clone(),
                });
            }
        }

        let msg_id = self.next_message_id;
        self.next_message_id += 1;
        self.total_messages += 1;

        // Read config values before mutable borrow.
        let drop_prob;
        let corrupt_bits;
        let reorder_depth;
        {
            let link = self.links.get(&link_id).unwrap();
            drop_prob = link.config.drop_probability;
            corrupt_bits = link.config.corrupt_bit_count;
            reorder_depth = link.config.reorder_depth;
        }

        // Drop decision.
        let roll = self.rng.next_f64();
        if roll < drop_prob {
            self.dropped_messages += 1;
            self.event_log.push(TransportEvent::MessageDropped {
                event_code: event_codes::VT_002.to_string(),
                message_id: msg_id,
                link_id: link_id.clone(),
            });
            return Ok(msg_id);
        }

        // Build the message.
        let mut msg_payload = payload;

        // Corruption.
        if corrupt_bits > 0 && !msg_payload.is_empty() {
            let bits_flipped = self.apply_corruption(&mut msg_payload, corrupt_bits);
            self.corrupted_messages += 1;
            self.event_log.push(TransportEvent::MessageCorrupted {
                event_code: event_codes::VT_004.to_string(),
                message_id: msg_id,
                link_id: link_id.clone(),
                bits_flipped,
            });
        }

        let msg = Message {
            id: msg_id,
            source: source.to_string(),
            target: target.to_string(),
            payload: msg_payload,
            tick_created: self.current_tick,
            tick_delivered: None,
        };

        // Enqueue with potential reordering.
        let link = self.links.get_mut(&link_id).unwrap();

        if reorder_depth > 0 && link.buffer.len() >= reorder_depth {
            // Insert at a deterministic position within the reorder window.
            let pos_raw = self.rng.next_u64() as usize;
            let window_start = if link.buffer.len() >= reorder_depth {
                link.buffer.len() - reorder_depth
            } else {
                0
            };
            let window_size = link.buffer.len() - window_start + 1;
            let insert_pos = window_start + (pos_raw % window_size);

            link.buffer.insert(insert_pos, msg);
            self.reordered_messages += 1;
            self.event_log.push(TransportEvent::MessageReordered {
                event_code: event_codes::VT_003.to_string(),
                message_id: msg_id,
                link_id: link_id.clone(),
                new_position: insert_pos,
            });
        } else {
            // Normal FIFO enqueue.
            link.buffer.push(msg);
            self.event_log.push(TransportEvent::MessageSent {
                event_code: event_codes::VT_001.to_string(),
                message_id: msg_id,
                link_id: link_id.clone(),
            });
        }

        Ok(msg_id)
    }

    /// Deliver the next message from a link's buffer, respecting delay.
    pub fn deliver_next(
        &mut self,
        link_id: &str,
    ) -> Result<Option<Message>, VirtualTransportError> {
        let link =
            self.links
                .get_mut(link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.to_string(),
                })?;

        if link.config.partition {
            return Err(VirtualTransportError::Partitioned {
                link_id: link_id.to_string(),
            });
        }

        if link.buffer.is_empty() {
            return Ok(None);
        }

        let delay = link.config.delay_ticks;
        let tick = self.current_tick;

        // Find the first message eligible for delivery (respecting delay).
        let eligible_idx = link
            .buffer
            .iter()
            .position(|msg| tick >= msg.tick_created.saturating_add(delay));

        match eligible_idx {
            Some(idx) => {
                let mut msg = link.buffer.remove(idx);
                msg.tick_delivered = Some(tick);
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Deliver all eligible messages from a link.
    pub fn deliver_all(&mut self, link_id: &str) -> Result<Vec<Message>, VirtualTransportError> {
        let mut delivered = Vec::new();
        while let Some(msg) = self.deliver_next(link_id)? {
            delivered.push(msg);
        }
        Ok(delivered)
    }

    /// Return the number of buffered (in-flight) messages on a link.
    pub fn buffered_count(&self, link_id: &str) -> Result<usize, VirtualTransportError> {
        let link = self
            .links
            .get(link_id)
            .ok_or_else(|| VirtualTransportError::LinkNotFound {
                link_id: link_id.to_string(),
            })?;
        Ok(link.buffer.len())
    }

    /// Return the total number of links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Update the fault configuration on an existing link.
    pub fn update_link_config(
        &mut self,
        link_id: &str,
        config: LinkFaultConfig,
    ) -> Result<(), VirtualTransportError> {
        config.validate()?;
        let link =
            self.links
                .get_mut(link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.to_string(),
                })?;
        link.config = config;
        Ok(())
    }

    /// Reset the transport layer to its initial state (keeps seed).
    pub fn reset(&mut self) {
        self.links.clear();
        self.total_messages = 0;
        self.dropped_messages = 0;
        self.reordered_messages = 0;
        self.corrupted_messages = 0;
        self.rng = Xorshift64::new(self.rng_seed);
        self.next_message_id = 1;
        self.current_tick = 0;
        self.event_log.clear();
    }

    /// Apply bit-level corruption to a payload. Returns actual bits flipped.
    fn apply_corruption(&mut self, payload: &mut [u8], bit_count: usize) -> usize {
        if payload.is_empty() {
            return 0;
        }
        let total_bits = payload.len() * 8;
        let actual_flips = bit_count.min(total_bits);
        for _ in 0..actual_flips {
            let bit_pos = (self.rng.next_u64() as usize) % total_bits;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            payload[byte_idx] ^= 1 << bit_idx;
        }
        actual_flips
    }
}

impl Default for VirtualTransportLayer {
    fn default() -> Self {
        Self::new(42)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test 1: schema version
    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "vt-v1.0");
        assert_eq!(BEAD_ID, "bd-2ko");
        assert_eq!(SECTION, "10.11");
    }

    // -- Test 2: create and destroy links
    #[test]
    fn test_create_and_destroy_link() {
        let mut vt = VirtualTransportLayer::new(42);
        let link_id = vt
            .create_link("node_a", "node_b", LinkFaultConfig::no_faults())
            .unwrap();
        assert_eq!(link_id, "node_a->node_b");
        assert_eq!(vt.link_count(), 1);

        let buffered = vt.destroy_link(&link_id).unwrap();
        assert!(buffered.is_empty());
        assert_eq!(vt.link_count(), 0);
    }

    // -- Test 3: duplicate link rejected
    #[test]
    fn test_duplicate_link_rejected() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        let err = vt
            .create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap_err();
        assert!(matches!(err, VirtualTransportError::LinkExists { .. }));
        let msg = format!("{}", err);
        assert!(msg.contains("ERR_VT_LINK_EXISTS"));
    }

    // -- Test 4: link not found error
    #[test]
    fn test_link_not_found() {
        let mut vt = VirtualTransportLayer::new(42);
        let err = vt.destroy_link("nonexistent->link").unwrap_err();
        assert!(matches!(err, VirtualTransportError::LinkNotFound { .. }));
        let msg = format!("{}", err);
        assert!(msg.contains("ERR_VT_LINK_NOT_FOUND"));
    }

    // -- Test 5: send and deliver message (no faults)
    #[test]
    fn test_send_and_deliver_no_faults() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        let payload = b"hello world".to_vec();
        let msg_id = vt.send_message("a", "b", payload.clone()).unwrap();
        assert!(msg_id > 0);
        assert_eq!(vt.total_messages, 1);

        let delivered = vt.deliver_next("a->b").unwrap().unwrap();
        assert_eq!(delivered.id, msg_id);
        assert_eq!(delivered.payload, payload);
        assert_eq!(delivered.source, "a");
        assert_eq!(delivered.target, "b");
        assert_eq!(delivered.tick_delivered, Some(0));
    }

    // -- Test 6: message delivery respects delay_ticks
    #[test]
    fn test_delay_ticks() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            delay_ticks: 5,
            ..Default::default()
        };
        vt.create_link("a", "b", config).unwrap();
        vt.send_message("a", "b", b"delayed".to_vec()).unwrap();

        // At tick 0, message should not be deliverable (created at 0, delay=5).
        let result = vt.deliver_next("a->b").unwrap();
        assert!(result.is_none());

        // Advance to tick 5: now eligible.
        vt.advance_tick(5);
        let delivered = vt.deliver_next("a->b").unwrap().unwrap();
        assert_eq!(delivered.payload, b"delayed".to_vec());
        assert_eq!(delivered.tick_delivered, Some(5));
    }

    // -- Test 7: partition blocks send
    #[test]
    fn test_partition_blocks_send() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            partition: true,
            ..Default::default()
        };
        vt.create_link("a", "b", config).unwrap();

        let err = vt.send_message("a", "b", b"blocked".to_vec()).unwrap_err();
        assert!(matches!(err, VirtualTransportError::Partitioned { .. }));
        let msg = format!("{}", err);
        assert!(msg.contains("ERR_VT_PARTITIONED"));
    }

    // -- Test 8: activate and heal partition
    #[test]
    fn test_activate_heal_partition() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        // Send works before partition.
        vt.send_message("a", "b", b"before".to_vec()).unwrap();

        // Activate partition.
        vt.activate_partition("a->b").unwrap();
        let err = vt.send_message("a", "b", b"during".to_vec()).unwrap_err();
        assert!(matches!(err, VirtualTransportError::Partitioned { .. }));

        // Heal partition.
        vt.heal_partition("a->b").unwrap();
        vt.send_message("a", "b", b"after".to_vec()).unwrap();
        assert_eq!(vt.total_messages, 2); // before + after (during was rejected)
    }

    // -- Test 9: drop probability drops messages
    #[test]
    fn test_drop_probability() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            drop_probability: 1.0,
            ..Default::default()
        };
        vt.create_link("a", "b", config).unwrap();

        for i in 0..10 {
            vt.send_message("a", "b", vec![i]).unwrap();
        }

        assert_eq!(vt.total_messages, 10);
        assert_eq!(vt.dropped_messages, 10);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 0);
    }

    // -- Test 10: zero drop probability delivers all
    #[test]
    fn test_zero_drop_delivers_all() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        for i in 0..5 {
            vt.send_message("a", "b", vec![i]).unwrap();
        }

        assert_eq!(vt.dropped_messages, 0);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 5);

        let delivered = vt.deliver_all("a->b").unwrap();
        assert_eq!(delivered.len(), 5);
    }

    // -- Test 11: corruption flips bits
    #[test]
    fn test_corruption() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            corrupt_bit_count: 3,
            ..Default::default()
        };
        vt.create_link("a", "b", config).unwrap();

        let original = vec![0u8; 16];
        vt.send_message("a", "b", original.clone()).unwrap();
        assert_eq!(vt.corrupted_messages, 1);

        let delivered = vt.deliver_next("a->b").unwrap().unwrap();
        // At least some bytes should differ due to corruption.
        assert_ne!(delivered.payload, original);
    }

    // -- Test 12: deterministic replay (INV-VT-DETERMINISTIC)
    #[test]
    fn test_deterministic_replay() {
        fn run_scenario(seed: u64) -> Vec<u64> {
            let mut vt = VirtualTransportLayer::new(seed);
            let config = LinkFaultConfig {
                drop_probability: 0.3,
                corrupt_bit_count: 1,
                ..Default::default()
            };
            vt.create_link("a", "b", config).unwrap();

            let mut msg_ids = Vec::new();
            for i in 0..20 {
                let id = vt.send_message("a", "b", vec![i as u8; 8]).unwrap();
                msg_ids.push(id);
            }
            msg_ids.push(vt.dropped_messages);
            msg_ids.push(vt.corrupted_messages);
            msg_ids
        }

        let run1 = run_scenario(12345);
        let run2 = run_scenario(12345);
        assert_eq!(
            run1, run2,
            "INV-VT-DETERMINISTIC violated: same seed must produce same results"
        );
    }

    // -- Test 13: different seeds produce different results
    #[test]
    fn test_different_seeds_diverge() {
        fn run_with_seed(seed: u64) -> u64 {
            let mut vt = VirtualTransportLayer::new(seed);
            let config = LinkFaultConfig {
                drop_probability: 0.5,
                ..Default::default()
            };
            vt.create_link("a", "b", config).unwrap();
            for i in 0..100 {
                let _ = vt.send_message("a", "b", vec![i as u8]);
            }
            vt.dropped_messages
        }

        let d1 = run_with_seed(1);
        let d2 = run_with_seed(999);
        // With 100 messages at 50% drop, different seeds should yield different drop counts.
        // This is probabilistic but extremely unlikely to fail.
        assert_ne!(
            d1, d2,
            "Different seeds should produce different fault patterns"
        );
    }

    // -- Test 14: invalid drop probability rejected
    #[test]
    fn test_invalid_probability_rejected() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            drop_probability: 1.5,
            ..Default::default()
        };
        let err = vt.create_link("a", "b", config).unwrap_err();
        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { .. }
        ));
        let msg = format!("{}", err);
        assert!(msg.contains("ERR_VT_INVALID_PROBABILITY"));
    }

    // -- Test 15: stats snapshot
    #[test]
    fn test_stats_snapshot() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.create_link(
            "b",
            "c",
            LinkFaultConfig {
                partition: true,
                ..Default::default()
            },
        )
        .unwrap();

        vt.send_message("a", "b", b"msg1".to_vec()).unwrap();
        vt.send_message("a", "b", b"msg2".to_vec()).unwrap();

        let stats = vt.stats();
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.dropped_messages, 0);
        assert_eq!(stats.active_links, 1);
        assert_eq!(stats.partitioned_links, 1);
    }

    // -- Test 16: event log records all events
    #[test]
    fn test_event_log() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"test".to_vec()).unwrap();
        vt.activate_partition("a->b").unwrap();
        vt.heal_partition("a->b").unwrap();

        let log = vt.event_log();
        assert!(log.len() >= 4); // link_created, message_sent, partition_activated, partition_healed

        // Check partition events.
        let partition_events: Vec<_> = log
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    TransportEvent::PartitionActivated { .. }
                        | TransportEvent::PartitionHealed { .. }
                )
            })
            .collect();
        assert_eq!(partition_events.len(), 2);
    }

    // -- Test 17: event codes are distinct
    #[test]
    fn test_event_codes_distinct() {
        let codes = [
            event_codes::VT_001,
            event_codes::VT_002,
            event_codes::VT_003,
            event_codes::VT_004,
            event_codes::VT_005,
            event_codes::VT_006,
            event_codes::VT_007,
            event_codes::VT_008,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate event code: {c}");
        }
        assert_eq!(seen.len(), 8);
    }

    // -- Test 18: error codes are distinct
    #[test]
    fn test_error_codes_distinct() {
        let codes = [
            error_codes::ERR_VT_LINK_EXISTS,
            error_codes::ERR_VT_LINK_NOT_FOUND,
            error_codes::ERR_VT_INVALID_PROBABILITY,
            error_codes::ERR_VT_PARTITIONED,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate error code: {c}");
        }
        assert_eq!(seen.len(), 4);
    }

    // -- Test 19: invariants are distinct
    #[test]
    fn test_invariants_distinct() {
        let invs = [
            invariants::INV_VT_DETERMINISTIC,
            invariants::INV_VT_DELIVERY_ORDER,
            invariants::INV_VT_DROP_RATE,
            invariants::INV_VT_CORRUPT_BITS,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for i in &invs {
            assert!(seen.insert(*i), "Duplicate invariant: {i}");
        }
        assert_eq!(seen.len(), 4);
    }

    // -- Test 20: reset clears state but preserves seed
    #[test]
    fn test_reset() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"msg".to_vec()).unwrap();
        assert_eq!(vt.total_messages, 1);

        vt.reset();
        assert_eq!(vt.total_messages, 0);
        assert_eq!(vt.link_count(), 0);
        assert!(vt.event_log().is_empty());
        assert_eq!(vt.rng_seed, 42);
    }

    // -- Test 21: update link config
    #[test]
    fn test_update_link_config() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        let new_config = LinkFaultConfig {
            drop_probability: 0.5,
            ..Default::default()
        };
        vt.update_link_config("a->b", new_config).unwrap();

        let link = vt.links.get("a->b").unwrap();
        assert!((link.config.drop_probability - 0.5).abs() < f64::EPSILON);
    }

    // -- Test 22: deliver_all returns all messages
    #[test]
    fn test_deliver_all() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        for i in 0..3 {
            vt.send_message("a", "b", vec![i]).unwrap();
        }

        let delivered = vt.deliver_all("a->b").unwrap();
        assert_eq!(delivered.len(), 3);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 0);
    }

    // -- Test 23: message Display implementation
    #[test]
    fn test_message_display() {
        let msg = Message {
            id: 1,
            source: "node_a".to_string(),
            target: "node_b".to_string(),
            payload: vec![0; 10],
            tick_created: 5,
            tick_delivered: None,
        };
        let display = format!("{}", msg);
        assert!(display.contains("id=1"));
        assert!(display.contains("node_a->node_b"));
        assert!(display.contains("10 bytes"));
        assert!(display.contains("tick=5"));
    }

    // -- Test 24: link_state link_id format
    #[test]
    fn test_link_state_link_id() {
        let ls = LinkState::new(
            "alpha".to_string(),
            "beta".to_string(),
            LinkFaultConfig::no_faults(),
        );
        assert_eq!(ls.link_id(), "alpha->beta");
        assert!(ls.active);
    }

    // -- Test 25: default transport layer
    #[test]
    fn test_default() {
        let vt = VirtualTransportLayer::default();
        assert_eq!(vt.rng_seed, 42);
        assert_eq!(vt.total_messages, 0);
        assert_eq!(vt.link_count(), 0);
    }
}
