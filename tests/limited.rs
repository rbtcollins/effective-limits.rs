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
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
#[cfg(windows)]
use winapi::shared::ntdef::NULL;

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
                    BasicLimitInformation: winapi::um::winnt::JOBOBJECT_BASIC_LIMIT_INFORMATION {
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
                        size_of::<winapi::um::winnt::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
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
                        effective_limits::Error::IoExplainedError(e, "error spawning helper".into())
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

#[test]
fn test_ulimit() -> Result<()> {
    // Page size rounding
    let limit = read_test_process(Some(99_999_744))?;
    assert_eq!(99_999_744, limit);
    Ok(())
}
