#![warn(clippy::all)]

extern crate effective_limits;

fn main() -> effective_limits::Result<()> {
    println!("Effective mem limit: {}", effective_limits::memory_limit()?);
    Ok(())
}
