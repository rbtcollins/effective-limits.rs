#![warn(clippy::all)]
// for error_chain!
#![recursion_limit = "1024"]

use std::cmp::min;

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

pub type Result<R> = std::result::Result<R, Error>;

fn min_opt(left: u64, right: Option<u64>) -> u64 {
    match right {
        None => left,
        Some(right) => min(left, right),
    }
}

#[cfg(unix)]
fn ulimited_memory() -> Result<Option<u64>> {
    #[cfg(all(not(target_os = "android"), not(target_env = "gnu")))]
    fn rlimit_as() -> libc::c_int {
        libc::RLIMIT_AS
    }
    #[cfg(all(not(target_os = "android"), target_env = "gnu"))]
    fn rlimit_as() -> libc::c_uint {
        libc::RLIMIT_AS
    }
    #[cfg(target_os = "android")]
    fn rlimit_as() -> libc::c_int {
        9 as libc::c_int
    }
    let mut out = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    match unsafe { libc::getrlimit(rlimit_as(), &mut out as *mut libc::rlimit) } {
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

#[cfg(not(unix))]
fn win_err<T>(fn_name: &str) -> Result<T> {
    Err(Error::IoExplainedError(
        std::io::Error::last_os_error(),
        fn_name.into(),
    ))
}

#[cfg(not(unix))]
fn ulimited_memory() -> Result<Option<u64>> {
    use std::mem::size_of;

    use winapi::shared::minwindef::{FALSE, LPVOID};
    use winapi::shared::ntdef::NULL;
    use winapi::um::jobapi2::QueryInformationJobObject;
    use winapi::um::winnt::{
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    let mut job_info = winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        ..Default::default()
    };
    let mut written: u32 = 0;
    // It is possible, even likely that this doesn't handle being run without a
    // job today, but hard to tell :/.
    match unsafe {
        QueryInformationJobObject(
            NULL,
            JobObjectExtendedLimitInformation,
            &mut job_info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as LPVOID,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            &mut written,
        )
    } {
        FALSE => win_err("QueryInformationJobObject"),
        _ => Ok(()),
    }?;
    if job_info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY
        == JOB_OBJECT_LIMIT_PROCESS_MEMORY
    {
        Ok(Some(job_info.ProcessMemoryLimit as u64))
    } else {
        Ok(None)
    }
}

/// How much memory is effectively available for this process to use,
/// considering the physical machine and ulimits, but not the impact of noisy
/// neighbours, swappiness and so on. The goal is to have a good chance of
/// avoiding failed allocations without requiring either developer or user
/// a-priori selection of memory limits.
pub fn memory_limit() -> Result<u64> {
    let info = sys_info::mem_info()?;
    let total_ram = info.total * 1024;
    let ulimit_mem = ulimited_memory()?;
    Ok(min_opt(total_ram, ulimit_mem))
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
    use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
    #[cfg(windows)]
    use winapi::shared::ntdef::NULL;

    use super::*;

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
                    use std::mem::size_of;
                    use std::process::Stdio;

                    cmd.creation_flags(winapi::um::winbase::CREATE_SUSPENDED);
                    let job = match unsafe {
                        winapi::um::winbase::CreateJobObjectA(
                            NULL as *mut winapi::um::minwinbase::SECURITY_ATTRIBUTES,
                            NULL as *const i8,
                        )
                    } {
                        NULL => win_err("CreateJobObjectA"),
                        handle => Ok(handle),
                    }?;
                    let mut job_info = winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                        BasicLimitInformation:
                            winapi::um::winnt::JOBOBJECT_BASIC_LIMIT_INFORMATION {
                                LimitFlags: winapi::um::winnt::JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                                ..Default::default()
                            },
                        ProcessMemoryLimit: ulimit as usize,
                        ..Default::default()
                    };
                    match unsafe {
                        winapi::um::jobapi2::SetInformationJobObject(
                            job,
                            winapi::um::winnt::JobObjectExtendedLimitInformation,
                            &mut job_info
                                as *mut winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                                as LPVOID,
                            size_of::<winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()
                                as u32,
                        )
                    } {
                        FALSE => win_err("SetInformationJobObject"),
                        _ => Ok(()),
                    }?;
                    let child = cmd
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| {
                            crate::Error::IoExplainedError(e, "error spawning helper".into())
                        })?;
                    let childhandle = match unsafe {
                        winapi::um::processthreadsapi::OpenProcess(
                            winapi::um::winnt::JOB_OBJECT_ASSIGN_PROCESS
                        // The docs say only JOB_OBJECT_ASSIGN_PROCESS is
                        // needed, but access denied is returned unless more
                        // permissions are requested, and the actual set needed
                        // is not documented.
                            | winapi::um::winnt::PROCESS_ALL_ACCESS,
                            FALSE,
                            child.id(),
                        )
                    } {
                        NULL => win_err("OpenProcess"),
                        handle => Ok(handle),
                    }?;
                    println!("assigning job {} pid {}", job as u32, childhandle as u32);
                    let res =
                        unsafe { winapi::um::jobapi2::AssignProcessToJobObject(job, childhandle) };
                    match res {
                        FALSE => win_err("AssignProcessToJobObject"),
                        _ => Ok(()),
                    }?;
                    let mut tid: DWORD = 0;
                    let tool = match unsafe {
                        winapi::um::tlhelp32::CreateToolhelp32Snapshot(
                            winapi::um::tlhelp32::TH32CS_SNAPTHREAD,
                            0,
                        )
                    } {
                        winapi::um::handleapi::INVALID_HANDLE_VALUE => {
                            win_err("CreateToolhelp32Snapshot")
                        }
                        handle => Ok(handle),
                    }?;
                    let mut te = winapi::um::tlhelp32::THREADENTRY32 {
                        dwSize: size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32,
                        ..Default::default()
                    };
                    match unsafe { winapi::um::tlhelp32::Thread32First(tool, &mut te) } {
                        FALSE => win_err("Thread32First"),
                        _ => Ok(()),
                    }?;
                    while {
                        if te.dwSize >= 16 /* owner proc id field offset */ &&te.th32OwnerProcessID == child.id()
                        {
                            tid = te.th32ThreadID;
                            // a break here would be nice.
                        };
                        te.dwSize = size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32;
                        match unsafe { winapi::um::tlhelp32::Thread32Next(tool, &mut te) } {
                            FALSE => {
                                let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
                                match err {
                                    winapi::shared::winerror::ERROR_NO_MORE_FILES => Ok(false),
                                    _ => win_err("Thread32Next"),
                                }
                            }
                            _ => Ok(true),
                        }?
                    } {}
                    match unsafe { winapi::um::handleapi::CloseHandle(tool) } {
                        FALSE => win_err("CloseHandle"),
                        _ => Ok(()),
                    }?;
                    let thread = match unsafe {
                        winapi::um::processthreadsapi::OpenThread(
                            winapi::um::winnt::THREAD_SUSPEND_RESUME,
                            FALSE,
                            tid,
                        )
                    } {
                        NULL => win_err("OpenThread"),
                        handle => Ok(handle),
                    }?;

                    match unsafe { winapi::um::processthreadsapi::ResumeThread(thread) } {
                        std::u32::MAX => win_err("ResumeThread"),
                        _ => Ok(()),
                    }?;
                    child.wait_with_output().map_err(|e| {
                        crate::Error::IoExplainedError(e, "error waiting for child".into())
                    })?
                }
                #[cfg(unix)]
                {
                    use std::io::Error;
                    unsafe {
                        cmd.pre_exec(move || {
                            let lim = libc::rlimit {
                                rlim_cur: ulimit,
                                rlim_max: libc::RLIM_INFINITY,
                            };
                            match libc::setrlimit(libc::RLIMIT_AS, &lim as *const libc::rlimit) {
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
