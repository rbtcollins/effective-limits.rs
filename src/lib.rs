#![warn(clippy::all)]
// for error_chain!
#![recursion_limit = "1024"]

use std::cmp::min;
#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::ptr;

use cfg_if::cfg_if;

#[cfg(windows)]
#[allow(
    dead_code,
    non_snake_case,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]
pub(crate) mod win_bindings;
#[cfg(windows)]
use win_bindings::{
    GetCurrentProcess, IsProcessInJob, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};

cfg_if! {
    if #[cfg(any(windows,
                 target_os="macos",
                 target_os="linux",
                 target_os="freebsd",
                 target_os="illumos",
                 target_os="solaris",
                 target_os="netbsd",
                 target_os="openbsd"
                ))] {
        #[derive(thiserror::Error, Debug)]
        pub enum Error {
            #[error("sysinfo failure")]
            SysInfo(#[from] ::sys_info::Error),
            #[error("io error")]
            IoError(#[from] std::io::Error),
            #[error("io error {1} ({0:?})")]
            IoExplainedError(#[source] std::io::Error, String),
            #[error("utf8 error")]
            Utf8Error(#[from] std::str::Utf8Error),
            #[error("u64 parse error on '{1}' ({0:?})")]
            U64Error(#[source] std::num::ParseIntError, String),
        }
    } else {
        #[derive(thiserror::Error, Debug)]
        pub enum Error {
            #[error("no system information on this platform")]
            SysInfo,
            #[error("io error")]
            IoError(#[from] std::io::Error),
            #[error("io error {1} ({0:?})")]
            IoExplainedError(#[source] std::io::Error, String),
            #[error("utf8 error")]
            Utf8Error(#[from] std::str::Utf8Error),
            #[error("u64 parse error on '{1}' ({0:?})")]
            U64Error(#[source] std::num::ParseIntError, String),
        }
    }
}

pub type Result<R> = std::result::Result<R, Error>;

#[allow(dead_code)]
fn min_opt(left: u64, right: Option<u64>) -> u64 {
    match right {
        None => left,
        Some(right) => min(left, right),
    }
}

#[allow(dead_code)]
#[cfg(all(unix, not(target_os = "openbsd")))]
fn ulimited_memory() -> Result<Option<u64>> {
    let mut out = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // https://github.com/rust-lang/libc/pull/1919
    cfg_if!(
    if #[cfg( target_os="netbsd")] {
    // https://github.com/NetBSD/src/blob/f869ef2144970023b53d335d9a23ecf100d4b973/sys/sys/resource.h#L98
    let rlimit_as = 10;
        }
    else {
    let rlimit_as = libc::RLIMIT_AS;
    }
    );
    match unsafe { libc::getrlimit(rlimit_as, &mut out as *mut libc::rlimit) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }?;
    let address_limit = match out.rlim_cur {
        libc::RLIM_INFINITY => None,
        _ => Some(out.rlim_cur as u64),
    };
    let mut out = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    match unsafe { libc::getrlimit(libc::RLIMIT_DATA, &mut out as *mut libc::rlimit) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }?;
    let data_limit = match out.rlim_cur {
        libc::RLIM_INFINITY => address_limit,
        _ => Some(out.rlim_cur as u64),
    };
    Ok(address_limit
        .or(data_limit)
        .map(|left| min_opt(left, data_limit)))
}

#[cfg(target_os = "openbsd")]
fn ulimited_memory() -> Result<Option<u64>> {
    Ok(None)
}

#[cfg(not(unix))]
fn win_err<T>(fn_name: &str) -> Result<T> {
    Err(Error::IoExplainedError(
        std::io::Error::last_os_error(),
        fn_name.into(),
    ))
}

#[cfg(feature = "integration_tests")]
pub mod testsupport {
    #[cfg(not(unix))]
    pub fn win_err<T>(fn_name: &str) -> crate::Result<T> {
        crate::win_err(fn_name)
    }
}

#[cfg(not(unix))]
fn ulimited_memory() -> Result<Option<u64>> {
    let mut in_job = 0;
    if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut in_job) } == 0 {
        return win_err("IsProcessInJob");
    }
    if in_job == 0 {
        return Ok(None);
    }

    let mut job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut written = 0;
    if unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            &mut job_info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            &mut written,
        )
    } == 0
    {
        return win_err("QueryInformationJobObject");
    }

    let flags = job_info.BasicLimitInformation.LimitFlags;
    match flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY as u32 == JOB_OBJECT_LIMIT_PROCESS_MEMORY as u32 {
        true => Ok(Some(job_info.ProcessMemoryLimit as u64)),
        false => Ok(None),
    }
}

/// How much memory is effectively available for this process to use,
/// considering the physical machine and ulimits, but not the impact of noisy
/// neighbours, swappiness and so on. The goal is to have a good chance of
/// avoiding failed allocations without requiring either developer or user
/// a-priori selection of memory limits.
pub fn memory_limit() -> Result<u64> {
    cfg_if! {
        if #[cfg(any(windows,
                     target_os="macos",
                     target_os="linux",
                     target_os="freebsd",
                     target_os="illumos",
                     target_os="solaris",
                     target_os="netbsd",
                     target_os="openbsd"
                    ))] {
            let info = sys_info::mem_info()?;
            let total_ram = info.total * 1024;
            let ulimit_mem = ulimited_memory()?;
            Ok(min_opt(total_ram, ulimit_mem))
        } else {
            // https://github.com/FillZpp/sys-info-rs/issues/72
            Err(Error::SysInfo)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(
        windows,
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[test]
    fn it_works() -> Result<()> {
        assert_ne!(0, memory_limit()?);
        Ok(())
    }

    #[test]
    fn test_min_opt() {
        assert_eq!(0, min_opt(0, None));
        assert_eq!(0, min_opt(0, Some(1)));
        assert_eq!(1, min_opt(2, Some(1)));
    }
}
