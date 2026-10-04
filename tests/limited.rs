// Functional tests that spawn the `test-limited` helper binary.
// Must be an integration test: CARGO_BIN_EXE_* is only set for those.

#![warn(clippy::all)]

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::str;

#[cfg(windows)]
#[allow(
    dead_code,
    non_snake_case,
    non_upper_case_globals,
    clippy::upper_case_acronyms
)]
#[path = "../src/win_bindings.rs"]
mod win_bindings;
#[cfg(windows)]
use win_bindings::{
    AssignProcessToJobObject, CloseHandle, CreateJobObjectA, CreateToolhelp32Snapshot,
    GetLastError, JobObjectExtendedLimitInformation, OpenProcess, OpenThread, ResumeThread,
    SetInformationJobObject, Thread32First, Thread32Next, CREATE_SUSPENDED, ERROR_NO_MORE_FILES,
    INVALID_HANDLE_VALUE, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_LIMIT_PROCESS_MEMORY, PROCESS_ALL_ACCESS,
    TH32CS_SNAPTHREAD, THREADENTRY32, THREAD_SUSPEND_RESUME,
};

#[cfg(unix)]
use cfg_if::cfg_if;
#[cfg(windows)]
use effective_limits::testsupport::win_err;
use effective_limits::{Error, Result};

fn test_process_path() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_test-limited"));
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

#[cfg(not(target_os = "openbsd"))]
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
                let job = match unsafe { CreateJobObjectA(ptr::null(), ptr::null()) } {
                    handle if handle.is_null() => win_err("CreateJobObjectA"),
                    handle => Ok(handle),
                }?;
                let job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                        LimitFlags: JOB_OBJECT_LIMIT_PROCESS_MEMORY as u32,
                        ..Default::default()
                    },
                    ProcessMemoryLimit: ulimit as usize,
                    ..Default::default()
                };
                match unsafe {
                    SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformation,
                        &job_info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const c_void,
                        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    )
                } {
                    0 => win_err("SetInformationJobObject"),
                    _ => Ok(()),
                }?;
                let child = cmd
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| {
                        effective_limits::Error::IoExplainedError(e, "error spawning helper".into())
                    })?;
                let childhandle = match unsafe {
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
                } {
                    handle if handle.is_null() => win_err("OpenProcess"),
                    handle => Ok(handle),
                }?;
                println!("assigning job {} pid {}", job as u32, childhandle as u32);
                let res = unsafe { AssignProcessToJobObject(job, childhandle) };
                match res {
                    0 => win_err("AssignProcessToJobObject"),
                    _ => Ok(()),
                }?;
                let mut tid: u32 = 0;
                let tool = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD as u32, 0) } {
                    handle if handle == INVALID_HANDLE_VALUE => win_err("CreateToolhelp32Snapshot"),
                    handle => Ok(handle),
                }?;
                let mut te = THREADENTRY32 {
                    dwSize: size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };
                match unsafe { Thread32First(tool, &mut te) } {
                    0 => win_err("Thread32First"),
                    _ => Ok(()),
                }?;
                while {
                    if te.dwSize >= 16 /* owner proc id field offset */ &&te.th32OwnerProcessID == child.id()
                    {
                        tid = te.th32ThreadID;
                        // a break here would be nice.
                    };
                    te.dwSize = size_of::<THREADENTRY32>() as u32;
                    match unsafe { Thread32Next(tool, &mut te) } {
                        0 => match unsafe { GetLastError() } {
                            err if err == ERROR_NO_MORE_FILES as u32 => Ok(false),
                            _ => win_err("Thread32Next"),
                        },
                        _ => Ok(true),
                    }?
                } {}
                match unsafe { CloseHandle(tool) } {
                    0 => win_err("CloseHandle"),
                    _ => Ok(()),
                }?;
                let thread = match unsafe { OpenThread(THREAD_SUSPEND_RESUME as u32, 0, tid) } {
                    handle if handle.is_null() => win_err("OpenThread"),
                    handle => Ok(handle),
                }?;

                match unsafe { ResumeThread(thread) } {
                    u32::MAX => win_err("ResumeThread"),
                    _ => Ok(()),
                }?;
                child.wait_with_output().map_err(|e| {
                    effective_limits::Error::IoExplainedError(e, "error waiting for child".into())
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
                    effective_limits::Error::IoExplainedError(e, "error running helper".into())
                })?
            }
        }
        None => cmd.output().map_err(|e| {
            effective_limits::Error::IoExplainedError(e, "error running helper".into())
        })?,
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

#[cfg(not(target_os = "openbsd"))]
#[test]
fn test_ulimit() -> Result<()> {
    // Page size rounding
    let limit = read_test_process(Some(99_999_744))?;
    assert_eq!(99_999_744, limit);
    Ok(())
}
