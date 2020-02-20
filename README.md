# Estimate effective resource limits for a process

`effective-limits` is a mid-level API for determining the effective limits upon
a process. It combines e.g. `mem_info` and `getrlimit`.

```rust
#![warn(clippy::all)]

extern crate effective_limits;

fn main() -> effective_limits::Result<()> {
    println!("Effective mem limit: {}", effective_limits::memory_limit()?);
    Ok(())
}
```
