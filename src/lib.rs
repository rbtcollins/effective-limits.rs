#![warn(clippy::all)]
// for error_chain!
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;

use std::cmp::min;
use std::convert::TryInto;

mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            SysInfo(::sys_info::Error);
        }
    }
}

pub use errors::*;

pub fn memory_limit() -> Result<u64> {
    let info = sys_info::mem_info()?;
    // XXX should this return u64?
    let total_ram = ((info.total * 1024) as usize)
        .try_into()
        .chain_err(|| "More memory than usize can represent")?;
    let mut out = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    match unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut out as *mut libc::rlimit) } {
        0 => Ok(()),
        _ => Err(format!("libc call failed {}", unsafe {
            *libc::__errno_location()
        })),
    }?;
    let address_limit = match out.rlim_cur {
        libc::RLIM_INFINITY => total_ram,
        _ => out.rlim_cur,
    };
    let mut out = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    match unsafe { libc::getrlimit(libc::RLIMIT_DATA, &mut out as *mut libc::rlimit) } {
        0 => Ok(()),
        _ => Err(format!("libc call failed {}", unsafe {
            *libc::__errno_location()
        })),
    }?;
    let data_limit = match out.rlim_cur {
        libc::RLIM_INFINITY => total_ram,
        _ => out.rlim_cur,
    };
    Ok(min(min(total_ram, address_limit), data_limit))
}

#[cfg(test)]
mod tests {
    use super::{memory_limit, Result};
    #[test]
    fn it_works() -> Result<()> {
        assert_ne!(0, memory_limit()?);
        Ok(())
    }
}
