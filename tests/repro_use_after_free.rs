//! Reproduction for GHSA-x9xc-63hg-vcfq: Use-after-free in cassandra-rs iterators
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
//! ## How to verify
//!
//! ```sh
//! # This test file should COMPILE on the vulnerable version (pre-3.0.0),
//! # proving the type system does not prevent the unsound usage.
//! cargo test --test repro_use_after_free -- --nocapture 2>&1
//! ```
//!
//! On the fixed version (3.0.0+), the `LendingIterator` trait replaces
//! `std::iter::Iterator`, tying each item's lifetime to `&mut self`, which
//! prevents both patterns at compile time.
//!
//! ## Note
//!
//! These tests demonstrate that the *type system allows* the unsound patterns.
//! Actually triggering the memory corruption at runtime requires a live
//! Cassandra cluster to produce real `CassResult` objects. The tests below
//! prove compilability of the dangerous patterns and exercise the API surface
//! with dummy pointers (carefully avoiding actual dereferences of freed memory
//! in the no-Cassandra-server case).

use cassandra_cpp::{CassResult, Row, Value};

// ---------------------------------------------------------------------------
// Vulnerability pattern 1: ResultIterator implements std::iter::Iterator,
// allowing .collect() which holds multiple Row references simultaneously.
// The C driver invalidates previous rows on each next() call.
// ---------------------------------------------------------------------------

/// This function demonstrates that the API allows collecting rows from
/// a ResultIterator into a Vec. With std::iter::Iterator, all collected
/// rows coexist, but the C driver has already invalidated all but the
/// last one - a use-after-free if any earlier row is accessed.
///
/// On the fixed version this does NOT compile because ResultIterator
/// implements LendingIterator (not Iterator), so .collect() is unavailable.
fn collect_rows_from_result(result: &CassResult) -> Vec<Row> {
    // This line compiles on the vulnerable version but not on the fixed version.
    // The std::iter::Iterator impl allows collecting, but the C driver
    // invalidates earlier rows when next() advances the iterator.
    result.iter().collect()
}

/// Demonstrates holding two rows simultaneously from the same iterator.
/// The second next() call invalidates the first row in the C driver,
/// but the Rust type system (incorrectly) allows both to coexist.
fn hold_two_rows_simultaneously(result: &CassResult) {
    let mut iter = result.iter();
    let _row1 = iter.next(); // first row
    let _row2 = iter.next(); // C driver invalidates row1's memory
    // _row1 is now a dangling pointer, but Rust considers it valid.
    // Any access to _row1 here would be a use-after-free.
}

// ---------------------------------------------------------------------------
// Vulnerability pattern 2: Row::into_iter() severs the lifetime chain.
// Row<'a> borrows CassResult, but into_iter() consumes the Row and returns
// a RowIterator with NO lifetime parameter. This allows CassResult to be
// dropped while RowIterator (and its Value items) still exist.
// ---------------------------------------------------------------------------

/// This function demonstrates the lifetime-erasure bug.
/// It takes ownership of a CassResult, extracts values from the first row
/// via into_iter(), then drops the CassResult. The returned Values hold
/// raw pointers into the freed CassResult memory.
///
/// On the fixed version, Row::into_iter() does not exist (replaced by
/// a lending iterator), preventing this pattern.
fn values_outlive_result(result: CassResult) -> Vec<Value> {
    let row = result.first_row().unwrap();
    // into_iter() consumes row, releasing the borrow on result.
    // The returned RowIterator has no lifetime parameter.
    let values: Vec<Value> = row.into_iter().collect();
    // result can now be dropped because the borrow was released
    drop(result);
    // `values` contains raw pointers into freed memory -> USE AFTER FREE
    values
}

/// Demonstrates that IntoIterator for &Row also produces lifetime-free Values.
fn ref_into_iter_erases_lifetime(result: &CassResult) -> Vec<Value> {
    let row = result.first_row().unwrap();
    // &row.into_iter() also produces a RowIterator with no lifetime
    let values: Vec<Value> = (&row).into_iter().collect();
    // row is dropped here, but values persist with no lifetime enforcement
    values
}

// ---------------------------------------------------------------------------
// Tests: these compile and run (as far as the type system is concerned).
// Without a Cassandra server, CassResult objects cannot be obtained, so
// these tests verify compilability rather than runtime behavior.
// ---------------------------------------------------------------------------

#[test]
fn test_vulnerable_api_compiles() {
    // The fact that these functions compile proves the API is unsound.
    // We cannot call them without a CassResult from a real Cassandra server,
    // but the type signatures alone demonstrate the vulnerability:

    // Verify function signatures are valid by referencing them as fn pointers
    let _: fn(&CassResult) -> Vec<Row> = collect_rows_from_result;
    let _: fn(&CassResult) = hold_two_rows_simultaneously;
    let _: fn(CassResult) -> Vec<Value> = values_outlive_result;
    let _: fn(&CassResult) -> Vec<Value> = ref_into_iter_erases_lifetime;

    println!("VULNERABILITY CONFIRMED: All unsound API patterns compile successfully.");
    println!();
    println!("Pattern 1: ResultIterator implements std::iter::Iterator");
    println!("  -> Allows .collect::<Vec<Row>>() which holds invalidated rows");
    println!("  -> The C driver invalidates previous rows on each next() call");
    println!("  -> Accessing collected rows is a use-after-free");
    println!();
    println!("Pattern 2: Row::into_iter() produces lifetime-free RowIterator/Values");
    println!("  -> Consumes Row (releases borrow on CassResult)");
    println!("  -> CassResult can be dropped while Values still hold raw pointers");
    println!("  -> Accessing these Values is a use-after-free");
    println!();
    println!("Fix: Replace std::iter::Iterator with LendingIterator (GATs)");
    println!("  -> Each item's lifetime is tied to &mut self on the iterator");
    println!("  -> Prevents collecting and holding multiple items simultaneously");
    println!("  -> Row::into_iter() is removed; Row::iter() returns a LendingIterator");
}
