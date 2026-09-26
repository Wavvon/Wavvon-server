//! Outbound voice packet loss, measured at the relay.
//!
//! A sender cannot know which of its own datagrams failed to arrive, so the
//! web client's connection panel could only ever show *inbound* loss. The relay
//! can: every voice packet carries a cleartext header
//! `[key_id: u32][ctr: u64][ts: u32]`, and `ctr` is the sender's own monotonic
//! packet counter. Gaps in it are packets that left the client and never
//! reached the hub — which is exactly what "outbound loss" means — and reading
//! them needs no decryption, so the end-to-end privacy model is untouched.
//! Same trick the client already uses on the receiving side.
//!
//! Deliberately the same arithmetic as `connectionStats.ts`, because the two
//! numbers sit next to each other in one panel: expected comes from the counter
//! span rather than from elapsed time (a silent participant sends nothing, and
//! time-based arithmetic would call that 100% loss), and reordering never moves
//! the highest-seen mark backwards.

/// Per-sender counter state. Reset when the sender joins voice, so the figure
/// describes the current session and not one from an hour ago.
#[derive(Debug, Clone, Copy)]
pub struct SenderLoss {
    /// Highest counter seen from this sender.
    pub highest_ctr: u64,
    /// Counter of the first packet seen, so expected is derivable.
    pub first_ctr: u64,
    /// Datagrams actually relayed.
    pub received: u64,
}

/// Byte offset of `ctr` in the sealed packet header.
const CTR_OFFSET: usize = 4;
const CTR_LEN: usize = 8;

/// Read the sender's packet counter out of a sealed datagram's cleartext
/// header. `None` for anything too short to have one, which the relay then
/// forwards untracked rather than dropping — measuring is not its job.
pub fn read_ctr(payload: &[u8]) -> Option<u64> {
    let bytes: [u8; CTR_LEN] = payload
        .get(CTR_OFFSET..CTR_OFFSET + CTR_LEN)?
        .try_into()
        .ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Fold one relayed datagram into a sender's tracker.
pub fn track(prev: Option<SenderLoss>, ctr: u64) -> SenderLoss {
    match prev {
        None => SenderLoss {
            highest_ctr: ctr,
            first_ctr: ctr,
            received: 1,
        },
        Some(p) => SenderLoss {
            highest_ctr: p.highest_ctr.max(ctr),
            first_ctr: p.first_ctr.min(ctr),
            received: p.received + 1,
        },
    }
}

/// Loss for one sender as a percentage, rounded to one decimal.
///
/// `None` while there is nothing to judge — a single packet has no span, and
/// reporting 0.0% from one datagram would be a fabricated number, the thing
/// the client's panel refused to do in the first place.
///
/// ponytail: cumulative over the session, so a long call dilutes a bad patch
/// into the average — same property the client's inbound figure has, and
/// keeping them identical matters more than either being clever. Move both to a
/// sliding window together if "is it bad right now" becomes the question.
pub fn loss_percent(t: Option<&SenderLoss>) -> Option<f32> {
    let t = t?;
    let expected = t.highest_ctr.saturating_sub(t.first_ctr) + 1;
    if expected <= 1 {
        return None;
    }
    let lost = expected.saturating_sub(t.received);
    if lost == 0 {
        return Some(0.0);
    }
    Some(((lost as f64 / expected as f64) * 1000.0).round() as f32 / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(ctr: u64) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&7u32.to_be_bytes()); // key_id
        p.extend_from_slice(&ctr.to_be_bytes());
        p.extend_from_slice(&960u32.to_be_bytes()); // ts
        p.extend_from_slice(&[0xAA; 32]); // ciphertext
        p
    }

    #[test]
    fn the_counter_is_read_from_the_cleartext_header() {
        assert_eq!(read_ctr(&packet(42)), Some(42));
        assert_eq!(read_ctr(&packet(u64::MAX)), Some(u64::MAX));
    }

    /// A runt datagram must not panic the relay — it forwards it untracked.
    #[test]
    fn a_packet_too_short_to_have_a_counter_is_not_read() {
        assert_eq!(read_ctr(&[]), None);
        assert_eq!(read_ctr(&[0; 11]), None);
        assert_eq!(read_ctr(&[0; 12]), Some(0));
    }

    #[test]
    fn a_clean_stream_reports_no_loss() {
        let mut t = None;
        for ctr in 0..100 {
            t = Some(track(t, ctr));
        }
        assert_eq!(loss_percent(t.as_ref()), Some(0.0));
    }

    #[test]
    fn a_gap_is_loss() {
        let mut t = None;
        // 100 counters span, 10 of them never arrived.
        for ctr in 0..100 {
            if (10..20).contains(&ctr) {
                continue;
            }
            t = Some(track(t, ctr));
        }
        assert_eq!(loss_percent(t.as_ref()), Some(10.0));
    }

    /// The property that makes this usable on a QUIC datagram path, where
    /// reordering is routine: out-of-order arrival is not loss.
    #[test]
    fn reordering_is_not_loss() {
        let mut t = None;
        for ctr in [0u64, 3, 1, 2, 5, 4] {
            t = Some(track(t, ctr));
        }
        assert_eq!(loss_percent(t.as_ref()), Some(0.0));
    }

    /// A silent participant sends nothing at all. Time-based arithmetic would
    /// call that total loss; counter-span arithmetic says "no idea yet".
    #[test]
    fn one_packet_is_not_enough_to_judge() {
        assert_eq!(loss_percent(None), None);
        assert_eq!(loss_percent(Some(&track(None, 9))), None);
    }
}
