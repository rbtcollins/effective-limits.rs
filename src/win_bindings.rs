windows_link::link!("kernel32.dll" "system" fn AssignProcessToJobObject(hjob : HANDLE, hprocess : HANDLE) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn CloseHandle(hobject : HANDLE) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn CreateJobObjectA(lpjobattributes : *const SECURITY_ATTRIBUTES, lpname : PCSTR) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn CreateToolhelp32Snapshot(dwflags : u32, th32processid : u32) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn GetCurrentProcess() -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn GetLastError() -> u32);
windows_link::link!("kernel32.dll" "system" fn IsProcessInJob(processhandle : HANDLE, jobhandle : HANDLE, result : *mut BOOL) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn OpenProcess(dwdesiredaccess : u32, binherithandle : BOOL, dwprocessid : u32) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn OpenThread(dwdesiredaccess : u32, binherithandle : BOOL, dwthreadid : u32) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn QueryInformationJobObject(hjob : HANDLE, jobobjectinformationclass : JOBOBJECTINFOCLASS, lpjobobjectinformation : *mut core::ffi::c_void, cbjobobjectinformationlength : u32, lpreturnlength : *mut u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn ResumeThread(hthread : HANDLE) -> u32);
windows_link::link!("kernel32.dll" "system" fn SetInformationJobObject(hjob : HANDLE, jobobjectinformationclass : JOBOBJECTINFOCLASS, lpjobobjectinformation : *const core::ffi::c_void, cbjobobjectinformationlength : u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn Thread32First(hsnapshot : HANDLE, lpte : *mut THREADENTRY32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn Thread32Next(hsnapshot : HANDLE, lpte : *mut THREADENTRY32) -> BOOL);
pub type BOOL = i32;
pub const CREATE_SUSPENDED: i32 = 4;
pub const ERROR_NO_MORE_FILES: i32 = 18;
pub type HANDLE = *mut core::ffi::c_void;
pub const INVALID_HANDLE_VALUE: HANDLE = -1 as _;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IO_COUNTERS {
    pub ReadOperationCount: u64,
    pub WriteOperationCount: u64,
    pub OtherOperationCount: u64,
    pub ReadTransferCount: u64,
    pub WriteTransferCount: u64,
    pub OtherTransferCount: u64,
}
pub type JOBOBJECTINFOCLASS = i32;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    pub PerProcessUserTimeLimit: i64,
    pub PerJobUserTimeLimit: i64,
    pub LimitFlags: u32,
    pub MinimumWorkingSetSize: usize,
    pub MaximumWorkingSetSize: usize,
    pub ActiveProcessLimit: u32,
    pub Affinity: usize,
    pub PriorityClass: u32,
    pub SchedulingClass: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    pub IoInfo: IO_COUNTERS,
    pub ProcessMemoryLimit: usize,
    pub JobMemoryLimit: usize,
    pub PeakProcessMemoryUsed: usize,
    pub PeakJobMemoryUsed: usize,
}
pub const JOB_OBJECT_ASSIGN_PROCESS: i32 = 1;
pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY: i32 = 256;
pub const JobObjectExtendedLimitInformation: JOBOBJECTINFOCLASS = 9;
pub type PCSTR = *const u8;
pub const PROCESS_ALL_ACCESS: i32 = 2097151;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut core::ffi::c_void,
    pub bInheritHandle: BOOL,
}
pub const TH32CS_SNAPTHREAD: i32 = 4;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}
pub const THREAD_SUSPEND_RESUME: i32 = 2;
