#![warn(clippy::all)]

extern crate effective_limits;

// Functional test helper for the library, not an end user script.
fn main() -> effective_limits::Result<()> {
    println!("{}", effective_limits::memory_limit()?);
    Ok(())
}
