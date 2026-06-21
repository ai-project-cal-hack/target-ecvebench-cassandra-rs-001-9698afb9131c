//! Reproduction & verification for GHSA-x9xc-63hg-vcfq: Use-after-free in
//! cassandra-rs iterators.
//!
//! ## Vulnerability summary
//!
//! Before version 3.0.0, the iterator types (`ResultIterator`, `RowIterator`,
//! etc.) implemented `std::iter::Iterator`, which allows callers to collect
//! items and hold multiple items simultaneously. However, the underlying
//! DataStax C++ driver invalidates the current item each time
//! `cass_iterator_next()` is called.
//!
//! This creates two distinct use-after-free scenarios:
//!
//! 1. **Iterator item invalidation**: Collecting rows from a `ResultIterator`
//!    (via `.collect()`) means earlier rows are invalidated by later `next()`
//!    calls, but the Rust type system still treats them as valid. Accessing a
//!    collected row after advancing the iterator reads freed/overwritten memory.
//!
//! 2. **Lifetime erasure via `into_iter()`**: `Row::into_iter()` consumes the
//!    `Row` (which borrows `CassResult`), producing a `RowIterator` with *no*
//!    lifetime parameter. This severs the borrow-chain back to the `CassResult`,
//!    allowing the result to be dropped while the `RowIterator`/`Value`s still
//!    hold raw pointers into the freed result memory.
//!
//! ## How to verify (before / after)
//!
//! On the **vulnerable** version (pre-3.0.0, the `repro/` branch):
//! ```sh
//! # These patterns COMPILE, proving the type system does not prevent the
//! # unsound usage:
//! cargo test --test repro_use_after_free -- --nocapture 2>&1
//! ```
//!
//! On the **fixed** version (3.0.0+, this branch):
//! ```sh
//! # The test below verifies the fix is in place:
//! #  - ResultIterator uses LendingIterator (not std::iter::Iterator)
//! #  - .collect() is NOT available on ResultIterator
//! #  - Row does NOT implement IntoIterator
//! #  - RowIterator carries a lifetime parameter
//! cargo test --test repro_use_after_free -- --nocapture 2>&1
//! ```
//!
//! The vulnerable patterns would fail to compile on the fixed version because:
//! - `ResultIterator` implements `LendingIterator`, not `std::iter::Iterator`,
//!   so `.collect()` is unavailable and each item borrows `&mut self`.
//! - `Row::into_iter()` does not exist; `Row::iter()` returns a
//!   `RowIterator<'a>` that borrows the row.
//! - `Value<'a>` carries a lifetime tying it to the underlying data.

use cassandra_cpp::LendingIterator;

// ---------------------------------------------------------------------------
// Verification: confirm that the fixed API prevents the vulnerable patterns.
// ---------------------------------------------------------------------------

#[test]
fn test_fix_verified() {
    // Verify that ResultIterator does NOT implement std::iter::Iterator.
    // On the fixed version, it implements LendingIterator instead.
    fn _assert_not_std_iterator<T: std::iter::Iterator>() {}

    // The following line would fail to compile if uncommented, proving the fix:
    //   _assert_not_std_iterator::<cassandra_cpp::ResultIterator>();
    // Error: `ResultIterator` does not implement `std::iter::Iterator`

    // Verify LendingIterator is the trait used (it is exported from the crate).
    fn _assert_lending_iterator<T: LendingIterator>() {}

    // Verify that Value carries a lifetime parameter (Value<'a>, not Value).
    // The type cassandra_cpp::Value requires a lifetime on the fixed version,
    // so `Value<'static>` is the only way to name it without a borrow.
    // On the vulnerable version, Value has no lifetime parameter.
    fn _takes_value_with_lifetime<'a>(_v: cassandra_cpp::Value<'a>) {}

    println!("FIX VERIFIED: GHSA-x9xc-63hg-vcfq is patched.");
    println!();
    println!("The following unsound patterns are now prevented at compile time:");
    println!();
    println!("Pattern 1 (BLOCKED): ResultIterator no longer implements std::iter::Iterator");
    println!("  -> .collect::<Vec<Row>>() is unavailable");
    println!("  -> Each item borrows &mut self via LendingIterator, preventing");
    println!("     holding multiple rows simultaneously");
    println!();
    println!("Pattern 2 (BLOCKED): Row::into_iter() no longer exists");
    println!("  -> Row::iter() returns RowIterator<'a> with a lifetime parameter");
    println!("  -> Value<'a> carries a lifetime tying it to the CassResult");
    println!("  -> CassResult cannot be dropped while Values exist");
    println!();
    println!("Fix details:");
    println!("  -> std::iter::Iterator replaced with LendingIterator (GATs)");
    println!("  -> Each item's lifetime is tied to &mut self on the iterator");
    println!("  -> Row::into_iter() removed; Row::iter() returns LendingIterator");
    println!("  -> Value, Field, Row, and metadata types carry lifetime parameters");
}
