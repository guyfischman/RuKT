// Draft-03 Appendix A: Implicit Binary Search Tree Logic

pub fn is_leaf(node_id: u64) -> bool {
    (node_id & 1) == 0
}

pub fn level(node_id: u64) -> u32 {
    if is_leaf(node_id) {
        return 0;
    }
    node_id.trailing_ones()
}

pub fn log2(n: u64) -> u32 {
    if n == 0 {
        return 0;
    }
    63 - n.leading_zeros()
}

// IBST root over n log entries (Appendix A)
pub fn root(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    (1 << log2(n)) - 1
}

// Merkle node id of the log tree root over n leaves (§11.8)
pub fn merkle_root(n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    let k = 64 - (n - 1).leading_zeros();
    (1 << k) - 1
}

pub fn left_child(x: u64) -> u64 {
    let k = level(x);
    if k == 0 {
        return x;
    }
    x ^ (1 << (k - 1))
}

pub fn chunk_id(node_id: u64) -> u64 {
    let mut c = node_id;
    let mut i = 0;
    while level(c) % 4 != 3 && i < 64 {
        let l = level(c);
        if l >= 62 {
            break;
        }
        let is_right = (c >> (l + 1)) & 1;
        let offset = 1u64 << l;
        if is_right == 1 {
            c -= offset;
        } else {
            c += offset;
        }
        i += 1;
    }
    c
}

pub fn chunk_layout(chunk_root: u64) -> [u64; 15] {
    let mut ids = [0u64; 15];
    ids[7] = chunk_root;
    fn internal_left(x: u64) -> u64 {
        x ^ (1 << (level(x) - 1))
    }
    fn internal_right(x: u64) -> u64 {
        x ^ (3 << (level(x) - 1))
    }
    ids[3] = internal_left(ids[7]);
    ids[11] = internal_right(ids[7]);
    ids[1] = internal_left(ids[3]);
    ids[5] = internal_right(ids[3]);
    ids[9] = internal_left(ids[11]);
    ids[13] = internal_right(ids[11]);
    ids[0] = internal_left(ids[1]);
    ids[2] = internal_right(ids[1]);
    ids[4] = internal_left(ids[5]);
    ids[6] = internal_right(ids[5]);
    ids[8] = internal_left(ids[9]);
    ids[10] = internal_right(ids[9]);
    ids[12] = internal_left(ids[13]);
    ids[14] = internal_right(ids[13]);
    ids
}

// MERKLE TREE Right Child (For Log Tree Construction/Proofs)
pub fn right_child(x: u64, n: u64) -> u64 {
    let k = level(x);
    if k == 0 {
        panic!("leaf node has no children");
    }

    let mut r = x ^ (3 << (k - 1));

    while leftmost_leaf_index(r) >= n {
        if is_leaf(r) {
            // right subtree entirely absent: the node collapses to its left child
            return left_child(x);
        }
        r = left_child(r);
    }
    r
}

fn leftmost_leaf_index(mut x: u64) -> u64 {
    while !is_leaf(x) {
        let k = level(x);
        x = x ^ (1 << (k - 1)); // Go left
    }
    x / 2
}

// IBST Right Child (For Timestamp Search)
// Valid for indices 0..n-1
pub fn ibst_right_child(mut x: u64, n: u64) -> Option<u64> {
    let k = level(x);
    if k == 0 {
        return None;
    }

    x ^= 3 << (k - 1);

    while x >= n {
        let k_curr = level(x);
        if k_curr == 0 {
            return None;
        }
        x = left_child(x);
    }
    Some(x)
}

pub fn get_roots(mut n: u64) -> Vec<u64> {
    let mut roots = Vec::new();
    let mut offset = 0;
    while n > 0 {
        let k = 1u64 << log2(n);
        let r = root(k) + (offset * 2);
        roots.push(r);
        offset += k;
        n -= k;
    }
    roots
}

pub fn parent(node_id: u64, _tree_size: u64) -> u64 {
    let l = level(node_id);
    if l >= 62 {
        return 0;
    }
    let is_right = (node_id >> (l + 1)) & 1;
    let offset = 1 << l;
    if is_right == 1 {
        node_id - offset
    } else {
        node_id + offset
    }
}

pub fn sibling(node_id: u64) -> u64 {
    let l = level(node_id);
    if l >= 62 {
        return 0;
    }
    let is_right = (node_id >> (l + 1)) & 1;
    let p = parent(node_id, 0);
    if is_right == 1 {
        p ^ (1 << (level(p) - 1))
    } else {
        p ^ (3 << (level(p) - 1))
    }
}

pub fn copath(mut node_id: u64, tree_size: u64) -> Vec<u64> {
    let mut path = Vec::new();
    let roots = get_roots(tree_size);
    if roots.contains(&node_id) {
        return path;
    }
    for _ in 0..100 {
        if roots.contains(&node_id) {
            break;
        }
        let p = parent(node_id, tree_size);
        let l = level(node_id);
        let is_right = if l < 62 { (node_id >> (l + 1)) & 1 } else { 0 };
        if is_right == 1 {
            path.push(sibling(node_id));
        } else {
            let std_right = p ^ (3 << (level(p) - 1));
            // This relies on Merkle ID check
            if leftmost_leaf_index(std_right) < tree_size {
                path.push(std_right);
            }
        }
        node_id = p;
    }
    path
}

pub fn consistency_proof(m: u64, n: u64) -> Vec<u64> {
    if m == 0 || m >= n {
        return Vec::new();
    }
    sub_proof(m, n, true)
}

fn sub_proof(m: u64, n: u64, b: bool) -> Vec<u64> {
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![root(m)];
    }
    let k = 1u64 << log2(n);
    let k = if k == n { k / 2 } else { k };
    if m <= k {
        let mut proof = sub_proof(m, k, b);
        proof.push(right_child(root(n), n)); // Using Merkle right_child (u64)
        return proof;
    } else {
        let mut proof = sub_proof(m - k, n - k, false);
        for i in 0..proof.len() {
            proof[i] += 2 * k;
        }
        let mut res = vec![left_child(root(n))];
        res.extend(proof);
        res
    }
}

pub fn get_frontier(tree_size: u64) -> Vec<u64> {
    let mut frontier = Vec::new();
    if tree_size == 0 {
        return frontier;
    }

    let mut curr = root(tree_size);
    frontier.push(curr);

    let rightmost = tree_size - 1;
    let mut safeguard = 0;
    while curr != rightmost && safeguard < 100 {
        if let Some(r) = ibst_right_child(curr, tree_size) {
            curr = r;
            frontier.push(curr);
        } else {
            break;
        }
        safeguard += 1;
    }
    frontier
}

pub fn direct_path(mut node_id: u64, tree_size: u64) -> Vec<u64> {
    let mut path = Vec::new();
    let roots = get_roots(tree_size);
    if roots.contains(&node_id) {
        return path;
    }
    for _ in 0..100 {
        node_id = parent(node_id, tree_size);
        path.push(node_id);
        if roots.contains(&node_id) {
            break;
        }
    }
    path
}

pub fn full_monitoring_path(node_id: u64, _start: u64, tree_size: u64) -> Vec<u64> {
    let mut path = Vec::new();
    let parents = direct_path(node_id, tree_size);
    for p in parents {
        if p > node_id {
            path.push(p);
        }
    }
    path.sort();
    path
}

pub fn rightmost_leaf(mut node_id: u64) -> u64 {
    while !is_leaf(node_id) {
        node_id ^= 3 << (level(node_id) - 1);
    }
    node_id
}

/// Returns the direct path (ancestors) of a node in the Implicit Binary Search Tree (IBST).
/// Unlike the Merkle direct_path, this strictly respects tree_size bounds.
// §8.3 first algorithm: the start entry, then its ancestors to its left,
// climbing toward the root (before expiry truncation).
pub fn owner_init_list(start: u64, n: u64) -> Vec<u64> {
    let mut list = vec![start];
    for a in ibst_direct_path(start, n) {
        if a < start {
            list.push(a);
        }
    }
    list
}

pub fn ibst_direct_path(target: u64, n: u64) -> Vec<u64> {
    let mut path = Vec::new();
    let mut curr_size = n;
    let mut offset = 0;

    while curr_size > 0 {
        let left_size = (1u64 << log2(curr_size)) - 1;
        let root_idx = offset + left_size;

        if target == root_idx {
            break;
        }

        path.push(root_idx);

        if target < root_idx {
            // Traverse Left
            curr_size = left_size;
        } else {
            // Traverse Right
            offset = root_idx + 1;
            curr_size = curr_size - left_size - 1;
        }
    }

    // Path was built from root down to target.
    // Ancestor paths are conventionally ordered from node up to root.
    path.reverse();
    path
}
