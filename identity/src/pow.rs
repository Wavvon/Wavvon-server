use sha2::{Digest, Sha256};

/// Count leading zero bits in a hash output.
pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Compute a proof-of-work nonce that achieves at least `target_level` leading zero bits.
/// Starts searching from `start_nonce`.
/// Returns (nonce, actual_level_achieved).
pub fn compute_security_level(
    public_key_hex: &str,
    start_nonce: u64,
    target_level: u32,
) -> (u64, u32) {
    let mut best_nonce = start_nonce;
    let mut best_level = 0;

    // Check the starting nonce first
    if start_nonce > 0 {
        best_level = hash_level(public_key_hex, start_nonce);
        if best_level >= target_level {
            return (best_nonce, best_level);
        }
    }

    let mut nonce = start_nonce;
    loop {
        nonce += 1;
        let level = hash_level(public_key_hex, nonce);

        if level > best_level {
            best_level = level;
            best_nonce = nonce;

            if best_level >= target_level {
                return (best_nonce, best_level);
            }
        }
    }
}

/// Verify that a given nonce achieves the claimed security level.
/// Returns true if SHA256(public_key_hex + nonce_bytes) has >= claimed_level leading zero bits.
pub fn verify_security_level(
    public_key_hex: &str,
    nonce: u64,
    claimed_level: u32,
) -> bool {
    if claimed_level == 0 {
        return true;
    }
    let level = hash_level(public_key_hex, nonce);
    level >= claimed_level
}

fn hash_level(public_key_hex: &str, nonce: u64) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(public_key_hex.as_bytes());
    hasher.update(&nonce.to_le_bytes());
    let result = hasher.finalize();
    leading_zero_bits(&result)
}
