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
#[cfg(unix)]
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

#[cfg(windows)]
pub(crate) fn win_err<T>(fn_name: &str) -> Result<T> {
    Err(Error::IoExplainedError(
        std::io::Error::last_os_error(),
        fn_name.into(),
    ))
}

#[cfg(windows)]
pub(crate) fn ulimited_memory() -> Result<Option<u64>> {
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
    use std::env;
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str;

    #[cfg(windows)]
    use crate::windows::bindings::*;
    #[cfg(windows)]
    use crate::windows::win_err;

    use super::*;

    #[cfg(any(
        windows,
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "netbsd",
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

    fn test_process_path() -> Option<PathBuf> {
        env::current_exe().ok().and_then(|p| {
            p.parent().map(|p| {
                p.with_file_name("test-limited")
                    .with_extension(env::consts::EXE_EXTENSION)
            })
        })
    }

    fn read_test_process(ulimit: Option<u64>) -> Result<u64> {
        // Spawn the test helper and read it's result.
        let path = test_process_path().unwrap();
        let mut cmd = Command::new(&path);
        let output = match ulimit {
            Some(ulimit) => {
                #[cfg(windows)]
                {
                    use std::ffi::c_void;
                    use std::mem::size_of;
                    use std::process::Stdio;
                    use std::ptr;

                    cmd.creation_flags(CREATE_SUSPENDED as u32);
                    let job = unsafe { CreateJobObjectA(ptr::null(), ptr::null()) };
                    if job.is_null() {
                        return win_err("CreateJobObjectA");
                    }

                    let job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                            LimitFlags: JOB_OBJECT_LIMIT_PROCESS_MEMORY as u32,
                            ..Default::default()
                        },
                        ProcessMemoryLimit: ulimit as usize,
                        ..Default::default()
                    };
                    if unsafe {
                        SetInformationJobObject(
                            job,
                            JobObjectExtendedLimitInformation,
                            &job_info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                                as *const c_void,
                            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                        )
                    } == 0
                    {
                        return win_err("SetInformationJobObject");
                    }

                    let child = cmd
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| {
                            crate::Error::IoExplainedError(e, "error spawning helper".into())
                        })?;
                    let childhandle = unsafe {
                        OpenProcess(
                            (JOB_OBJECT_ASSIGN_PROCESS
                        // The docs say only JOB_OBJECT_ASSIGN_PROCESS is
                        // needed, but access denied is returned unless more
                        // permissions are requested, and the actual set needed
                        // is not documented.
                            | PROCESS_ALL_ACCESS) as u32,
                            0,
                            child.id(),
                        )
                    };
                    if childhandle.is_null() {
                        return win_err("OpenProcess");
                    }

                    println!("assigning job {:?} pid {}", job, child.id());
                    if unsafe { AssignProcessToJobObject(job, childhandle) } == 0 {
                        return win_err("AssignProcessToJobObject");
                    }

                    let mut tid = 0;
                    let tool = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD as u32, 0) };
                    if tool == INVALID_HANDLE_VALUE {
                        return win_err("CreateToolhelp32Snapshot");
                    }

                    let mut te = THREADENTRY32 {
                        dwSize: size_of::<THREADENTRY32>() as u32,
                        ..Default::default()
                    };
                    if unsafe { Thread32First(tool, &mut te) } == 0 {
                        return win_err("Thread32First");
                    }
                    while {
                        if te.dwSize >= 16 /* owner proc id field offset */ &&te.th32OwnerProcessID == child.id()
                        {
                            tid = te.th32ThreadID;
                            // a break here would be nice.
                        };
                        te.dwSize = size_of::<THREADENTRY32>() as u32;
                        match unsafe { Thread32Next(tool, &mut te) } {
                            0 => match unsafe { GetLastError() } {
                                e if e == ERROR_NO_MORE_FILES as u32 => Ok(false),
                                _ => win_err("Thread32Next"),
                            },
                            _ => Ok(true),
                        }?
                    } {}
                    if unsafe { CloseHandle(tool) } == 0 {
                        return win_err("CloseHandle");
                    }

                    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME as u32, 0, tid) };
                    if thread.is_null() {
                        return win_err("OpenThread");
                    }
                    if unsafe { ResumeThread(thread) } == u32::MAX {
                        return win_err("ResumeThread");
                    }

                    child.wait_with_output().map_err(|e| {
                        crate::Error::IoExplainedError(e, "error waiting for child".into())
                    })?
                }
                #[cfg(unix)]
                {
                    use std::io::Error;
                    // https://github.com/rust-lang/libc/pull/1919
                    cfg_if!(
                    if #[cfg( target_os="netbsd")] {
                    let rlimit_as = 10;
                        }
                    else {
                    let rlimit_as = libc::RLIMIT_AS;
                    }
                    );
                    unsafe {
                        cmd.pre_exec(move || {
                            let lim = libc::rlimit {
                                rlim_cur: ulimit,
                                rlim_max: libc::RLIM_INFINITY,
                            };
                            match libc::setrlimit(rlimit_as, &lim as *const libc::rlimit) {
                                0 => Ok(()),
                                _ => Err(Error::last_os_error()),
                            }
                        });
                    }
                    cmd.output().map_err(|e| {
                        crate::Error::IoExplainedError(e, "error running helper".into())
                    })?
                }
            }
            None => cmd
                .output()
                .map_err(|e| crate::Error::IoExplainedError(e, "error running helper".into()))?,
        };
        assert_eq!(true, output.status.success());
        eprintln!("stderr {}", str::from_utf8(&output.stderr).unwrap());
        let limit_bytes = output.stdout;
        let limit: u64 = str::from_utf8(&limit_bytes)?
            .trim()
            .parse()
            .map_err(|e| Error::U64Error(e, str::from_utf8(&limit_bytes).unwrap().into()))?;

        Ok(limit)
    }

    #[cfg(any(
        windows,
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "solaris",
    ))]
    #[test]
    fn test_no_ulimit() -> Result<()> {
        // This test depends on the dev environment being run uncontained.
        let info = sys_info::mem_info()?;
        let total_ram = info.total * 1024;
        let limit = read_test_process(None)?;
        assert_eq!(total_ram, limit);
        Ok(())
    }

    #[test]
    fn test_ulimit() -> Result<()> {
        // Page size rounding
        let limit = read_test_process(Some(99_999_744))?;
        assert_eq!(99_999_744, limit);
        Ok(())
    }
}
