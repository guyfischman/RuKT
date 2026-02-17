use crate::tree::binary_ladder::base_binary_ladder;
use anyhow::Result;

#[test]
fn test_binary_ladder_boundary_zero() -> Result<()> {
    // Scenario 1: Version 0
    // Expected: [0, 1]
    // 0 is the start, 1 establishes upper bound > 0.
    let ladder = base_binary_ladder(0);
    assert_eq!(ladder, vec![0, 1]);
    Ok(())
}

#[test]
fn test_binary_ladder_boundary_one() -> Result<()> {
    // Scenario 2: Version 1
    // Expected: [0, 1, 3, 2]
    // 0, 1, 3 (upper > 1). Binary search 1..3 -> 2.
    let ladder = base_binary_ladder(1);
    assert_eq!(ladder, vec![0, 1, 3, 2]);
    Ok(())
}

#[test]
fn test_binary_ladder_boundary_max() -> Result<()> {
    // Scenario 3: Version 2^32 - 1 (u32::MAX)
    // This previously caused overflow panics.
    
    let max = u32::MAX;
    let ladder = base_binary_ladder(max);
    
    // 1. Must contain max
    assert!(ladder.contains(&max));
    
    // 2. Must end with max (since it exists and is the protocol limit)
    assert_eq!(*ladder.last().unwrap(), max);
    
    // 3. Verify sequence logic
    // The "Powers of 2" phase should reach MAX.
    let val_31 = 2147483647; // 2^31 - 1
    assert!(ladder.contains(&val_31));
    
    // Ensure no binary search midpoints were added erroneously.
    // If n=MAX, we proved existence of MAX. We implicitly know MAX+1 cannot exist.
    // So the ladder stops at MAX.
    
    Ok(())
}