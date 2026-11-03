use super::{EarlyShaper, ShapeDirection, ShapePlan};

/// Deterministic `draw`: a small LCG mapped into `lo..=hi`.
fn lcg(seed: u64) -> impl FnMut(usize, usize) -> usize {
    let mut s = seed;
    move |lo, hi| {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        lo + (s >> 33) as usize % (hi - lo + 1)
    }
}

fn sum(plan: &ShapePlan) -> usize {
    plan.pieces.iter().sum()
}

#[test]
fn client_pieces_stay_in_browser_range_and_sum_to_message() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
        let plan = s.plan(1964, &mut d);
        assert_eq!(sum(&plan), 1964, "seed {seed}");
        let (last, head) = plan.pieces.split_last().unwrap();
        assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
        for p in head {
            assert!((300..=850).contains(p), "seed {seed}: {plan:?}");
        }
        assert!((300..=850 + 299).contains(last), "seed {seed}: {plan:?}");
    }
}

#[test]
fn server_pieces_stay_in_range_and_sum_to_message() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, true, &mut d);
        let plan = s.plan(4499, &mut d);
        assert_eq!(sum(&plan), 4499);
        assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
        let (last, head) = plan.pieces.split_last().unwrap();
        for p in head {
            assert!((600..=2800).contains(p), "seed {seed}: {plan:?}");
        }
        assert!((600..=2800 + 599).contains(last), "seed {seed}: {plan:?}");
        assert!(plan.covers.is_empty(), "server never sends lead-in covers");
    }
}

#[test]
fn small_messages_are_not_split() {
    let mut d = lcg(7);
    let mut c = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
    assert_eq!(c.plan(900, &mut d).pieces, vec![900]);
    let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, true, &mut d);
    assert_eq!(s.plan(1500, &mut d).pieces, vec![1500]);
}

#[test]
fn window_closes_after_message_count() {
    let mut d = lcg(3);
    let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
    let mut split = 0;
    for _ in 0..20 {
        if s.plan(1200, &mut d).pieces.len() > 1 {
            split += 1;
        }
    }
    assert!((6..=10).contains(&split), "split {split} messages");
    assert!(!s.is_active());
    assert_eq!(s.plan(5000, &mut d).pieces, vec![5000]);
}

#[test]
fn window_closes_after_byte_budget_and_only_the_head_is_split() {
    let mut d = lcg(11);
    let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, true, &mut d);
    let plan = s.plan(100_000, &mut d);
    assert_eq!(sum(&plan), 100_000);
    let shaped: usize = plan.pieces[..plan.pieces.len() - 1].iter().sum();
    assert!(shaped <= 24_576 + 2800, "shaped {shaped}");
    assert!(*plan.pieces.last().unwrap() >= 100_000 - 24_576 - 2800);
    assert!(!s.is_active());
}

#[test]
fn client_covers_come_once_before_the_first_big_message() {
    let mut with_covers = 0;
    for seed in 0..400 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
        assert!(s.plan(200, &mut d).covers.is_empty(), "small message gets no cover");
        let first = s.plan(1964, &mut d);
        assert!(first.covers.len() <= 2);
        for c in &first.covers {
            assert!((40..=100).contains(c));
        }
        if !first.covers.is_empty() {
            with_covers += 1;
        }
        assert!(s.plan(1964, &mut d).covers.is_empty(), "covers come once");
    }
    assert!((120..=280).contains(&with_covers), "about half: {with_covers}/400");
}

#[test]
fn threshold_plus_one_is_split_in_both_directions() {
    for seed in 0..200 {
        for (dir, len, lo, hi) in [
            (ShapeDirection::ClientToServer, 901, 300, 850),
            (ShapeDirection::ServerToClient, 1501, 600, 2800),
        ] {
            let mut d = lcg(seed);
            let mut s = EarlyShaper::new(dir, true, &mut d);
            let plan = s.plan(len, &mut d);
            assert_eq!(sum(&plan), len, "seed {seed}");
            assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
            let (last, head) = plan.pieces.split_last().unwrap();
            for p in head {
                assert!((lo..=hi).contains(p), "seed {seed}: {plan:?}");
            }
            assert!((lo..=hi + lo - 1).contains(last), "seed {seed}: {plan:?}");
        }
    }
}

#[test]
fn covers_only_accompany_a_split_message() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
        let plan = s.plan(950, &mut d);
        if !plan.covers.is_empty() {
            assert!(plan.pieces.len() >= 2, "seed {seed}: {plan:?}");
        }
    }
}

#[test]
fn empty_message_does_not_consume_the_window() {
    let mut d = lcg(5);
    let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, true, &mut d);
    for _ in 0..20 {
        assert_eq!(s.plan(0, &mut d).pieces, vec![0]);
    }
    assert!(s.plan(1964, &mut d).pieces.len() >= 2);
}

#[test]
fn tiny_budget_left_does_not_split() {
    for seed in 0..200 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ServerToClient, true, &mut d);
        let first = s.plan(23_000, &mut d);
        assert_eq!(sum(&first), 23_000, "seed {seed}");
        let second = s.plan(4000, &mut d);
        assert_eq!(sum(&second), 4000, "seed {seed}: {second:?}");
        if second.pieces.len() > 1 {
            // Split only the shaped head; every piece but the last is in range.
            let (_, head) = second.pieces.split_last().unwrap();
            for p in head {
                assert!((600..=2800).contains(p), "seed {seed}: {second:?}");
            }
        }
    }
}

#[test]
fn covers_disallowed_never_emits_covers() {
    for seed in 0..400 {
        let mut d = lcg(seed);
        let mut s = EarlyShaper::new(ShapeDirection::ClientToServer, false, &mut d);
        for _ in 0..4 {
            let plan = s.plan(1964, &mut d);
            assert!(plan.covers.is_empty(), "seed {seed}");
            assert_eq!(sum(&plan), 1964);
        }
    }
}
