use chrono::{TimeZone, Utc};
use lazy_static::lazy_static;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::time;

const fn mask(start: usize, bits: usize) -> i64 {
  assert!((start + bits) <= 63, "bit overflow into the sign bit");
  ((1 << bits) - 1) << start
}

const fn base_mask(bits: usize) -> i64 {
  mask(0, bits)
}

const NODE_BITS: usize = 8;
const SEQUENCE_BITS: usize = 12;
const TIMESTAMP_BITS: usize = 43;

const NODE_SHIFT: usize = 0;
const SEQUENCE_SHIFT: usize = NODE_SHIFT + NODE_BITS;
const TIMESTAMP_SHIFT: usize = SEQUENCE_SHIFT + SEQUENCE_BITS;

const NODE_MASK: i64 = mask(NODE_SHIFT, NODE_BITS);
const SEQUENCE_MASK: i64 = mask(SEQUENCE_SHIFT, SEQUENCE_BITS);
const TIMESTAMP_MASK: i64 = mask(TIMESTAMP_SHIFT, TIMESTAMP_BITS);

const MAX_NODE: i64 = base_mask(NODE_BITS);
const MAX_SEQUENCE: i64 = base_mask(SEQUENCE_BITS);

const SEQUENCE_EXHAUSTED_DELAY: Duration = Duration::from_micros(100);

lazy_static! {
  static ref EPOCH: i64 = Utc
    .with_ymd_and_hms(2024, 3, 6, 8, 49, 54)
    .unwrap()
    .timestamp();
}

fn timestamp() -> i64 {
  Utc::now().timestamp() - *EPOCH
}

struct Snowflake {
  timestamp: i64,
  sequence: i64,
  node: i64,
}

fn pack(snowflake: Snowflake) -> i64 {
  (snowflake.timestamp << TIMESTAMP_SHIFT)
    | (snowflake.sequence << SEQUENCE_SHIFT)
    | (snowflake.node << NODE_SHIFT)
}

fn unpack(id: i64) -> Snowflake {
  Snowflake {
    timestamp: (id & TIMESTAMP_MASK) >> TIMESTAMP_SHIFT,
    sequence: (id & SEQUENCE_MASK) >> SEQUENCE_SHIFT,
    node: (id & NODE_MASK) >> NODE_SHIFT,
  }
}

/// Thread-safe snowflake ID generator with the following layout:
/// | 1 bit | 43 bits   | 12 bits  | 8 bits |
/// | sign  | timestamp | sequence | node   |
///
/// The epoch is 2024 Mar 6 8:49:54, the first commit of Just Host. A 43 bit
/// timestamp allows enough space to generate valid timestamps for another ~278
/// years, until the year ~2300.
///
/// The timestamp must use the highest bits to preserve monotonicity, otherwise
/// a previous timestamp with a larger sequence or node number would create an
/// ID larger than the ID with the current timestamp.
///
/// If we want to avoid generating consecutive IDs for objects generated at the
/// same time, we want to avoid putting the sequence at the lowest bits,
/// therefore we put it in the middle and leave the node at the lowst bits.
pub struct SnowflakeGenerator {
  id: AtomicI64,
}

impl SnowflakeGenerator {
  pub fn new(table_index: i64) -> Self {
    assert!(table_index <= MAX_NODE, "max node overflow");

    Self {
      id: AtomicI64::new(pack(Snowflake {
        timestamp: timestamp(),
        sequence: 0,
        node: table_index,
      })),
    }
  }

  pub async fn generate_id(&self) -> i64 {
    let mut last_id = self.id.load(Ordering::Relaxed);
    loop {
      let Snowflake {
        timestamp: last_timestamp,
        sequence: last_sequence,
        node: last_node,
      } = unpack(last_id);

      let timestamp = timestamp();
      let sequence = if timestamp == last_timestamp {
        last_sequence + 1
      } else {
        0
      };

      if sequence > MAX_SEQUENCE {
        time::sleep(SEQUENCE_EXHAUSTED_DELAY).await;
        last_id = self.id.load(Ordering::Relaxed);
        continue;
      }

      let new_id = pack(Snowflake {
        timestamp,
        sequence,
        node: last_node,
      });

      match self
        .id
        .compare_exchange(last_id, new_id, Ordering::Relaxed, Ordering::Relaxed)
      {
        Ok(_) => break new_id,
        Err(id) => last_id = id,
      }
    }
  }
}
