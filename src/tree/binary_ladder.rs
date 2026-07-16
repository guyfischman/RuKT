/// Returns the set of versions that would be looked up to establish that n was
/// the greatest version of a label that existed.
/// Corresponds to Draft-03 Appendix B `base_binary_ladder`.
pub fn base_binary_ladder(n: u32) -> Vec<u32> {
    let mut out = Vec::new();

    // Output powers of two minus one until reaching a value greater than n.
    loop {
        let len = out.len() as u32;
        // 2^len - 1
        // Use u64 to prevent overflow during calculation
        let value_u64 = (1u64 << len).saturating_sub(1);

        let value = if value_u64 > u32::MAX as u64 {
            u32::MAX
        } else {
            value_u64 as u32
        };

        // Prevent duplicates (e.g. at u32::MAX boundary)
        if let Some(&last) = out.last()
            && value == last
        {
            break;
        }

        out.push(value);

        if value > n {
            break;
        }

        // Optimization: if we reached the max possible value, we can't go higher.
        if value == u32::MAX {
            break;
        }
    }

    if out.len() < 2 {
        return out;
    }

    // Only binary search if the last value established an upper bound (non-inclusion)
    // If the last value is <= n, it means we hit the protocol limit (u32::MAX)
    // and proved it exists. No further search is needed.
    if out.last().is_some_and(|&v| v > n) {
        // Binary search between the established lower and upper bounds.
        let mut lower_bound = out[out.len() - 2];
        let mut upper_bound = out[out.len() - 1];

        // Ensure loop condition doesn't overflow if lower_bound is u32::MAX (though unlikely here given logic)
        while lower_bound < upper_bound && (upper_bound - lower_bound) > 1 {
            // Prevent overflow in midpoint calculation: (L+R)/2 can overflow u32
            let value = lower_bound + (upper_bound - lower_bound) / 2;

            out.push(value);
            if value <= n {
                lower_bound = value;
            } else {
                upper_bound = value;
            }
        }
    }

    out
}

/// Appendix B `search_binary_ladder`: target version t, greatest version existing
/// in the given prefix tree n.
pub fn search_binary_ladder(
    t: u32,
    n: u32,
    left_inclusion: &[u32],
    right_non_inclusion: &[u32],
) -> Vec<u32> {
    let out = base_binary_ladder(n);

    // (Proof of inclusion for a version greater than t) OR
    // (Proof of non-inclusion for a version less than or equal to t)
    let end = out
        .iter()
        .position(|&v| (v <= n && v > t) || (v > n && v <= t))
        .map(|i| i + 1)
        .unwrap_or(out.len());

    out.into_iter()
        .take(end)
        .filter(|&v| !left_inclusion.contains(&v) && !right_non_inclusion.contains(&v))
        .collect()
}

/// Appendix B `monitoring_binary_ladder`: monitored version of the label is t.
pub fn monitoring_binary_ladder(t: u32, left_inclusion: &[u32]) -> Vec<u32> {
    let out = base_binary_ladder(t);
    out.into_iter()
        .filter(|&v| v <= t && !left_inclusion.contains(&v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_binary_ladder_0() {
        let res = base_binary_ladder(0);
        assert_eq!(res, vec![0, 1]);
    }

    #[test]
    fn test_base_binary_ladder_1() {
        let res = base_binary_ladder(1);
        assert_eq!(res, vec![0, 1, 3, 2]);
    }

    #[test]
    fn test_base_binary_ladder_6() {
        let res = base_binary_ladder(6);
        assert_eq!(res, vec![0, 1, 3, 7, 5, 6]);
    }

    #[test]
    fn test_search_binary_ladder_continues_past_equal_target() {
        // §6.2: the ladder ends at the first inclusion proof for a version
        // strictly greater than the target, not merely equal to it
        assert_eq!(search_binary_ladder(1, 1, &[], &[]), vec![0, 1, 3, 2]);
        assert_eq!(search_binary_ladder(2, 6, &[], &[]), vec![0, 1, 3]);
        assert_eq!(search_binary_ladder(7, 3, &[], &[]), vec![0, 1, 3, 7]);
    }

    #[test]
    fn test_search_binary_ladder_dedup() {
        assert_eq!(search_binary_ladder(1, 1, &[0], &[]), vec![1, 3, 2]);
        assert_eq!(search_binary_ladder(1, 1, &[], &[3]), vec![0, 1, 2]);
    }

    #[test]
    fn test_monitoring_binary_ladder() {
        assert_eq!(monitoring_binary_ladder(6, &[]), vec![0, 1, 3, 5, 6]);
        assert_eq!(monitoring_binary_ladder(6, &[0, 1]), vec![3, 5, 6]);
    }

    #[test]
    fn test_base_binary_ladder_boundary_max() {
        // This test ensures no panic/overflow for u32::MAX
        let n = u32::MAX;
        let res = base_binary_ladder(n);

        // Should contain u32::MAX
        assert!(res.contains(&u32::MAX));
        // Should end with u32::MAX
        assert_eq!(*res.last().unwrap(), u32::MAX);
        // Should not have duplicates
        let mut dedup = res.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), res.len());

        // The last element before max should be 2^31 - 1
        let val_31 = 2147483647; // 2^31 - 1
        assert!(res.contains(&val_31));

        // Since MAX is included, we do NOT expect binary search midpoints.
        // We verified MAX exists, and nothing > MAX can exist.
    }
}
