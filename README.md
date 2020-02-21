# Estimate effective resource limits for a process

`effective-limits` is a mid-level API for determining the effective limits upon
a process. It combines e.g. `mem_info` and `getrlimit`.

The goal is to have a good chance of avoiding failed allocations without requiring either developer or user a-priori
selection of memory limits. That is, how much memory is effectively available for this process to use, considering the
physical machine and ulimits, but not the impact of noisy neighbours, swappiness and so on. This limit can then be used
to inform the size of in memory caches, put a threshold on in or output file buffers and so on.

```rust
#![warn(clippy::all)]

extern crate effective_limits;

fn main() -> effective_limits::Result<()> {
    println!("Effective mem limit: {}", effective_limits::memory_limit()?);
    Ok(())
}
```
