// Regenerates `src/win_bindings.rs` from the Windows metadata. The file is
// always rewritten; the test fails (showing a diff) if it was out of date.

use std::fs;
use std::path::Path;

#[test]
fn win_bindings() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/win_bindings.rs");
    let old = fs::read_to_string(&path).unwrap_or_default();

    windows_bindgen::Bindgen::new()
        .output(&path)
        .flat()
        .sys()
        .filters([
            "AssignProcessToJobObject",
            "CloseHandle",
            "CREATE_SUSPENDED",
            "CreateJobObjectA",
            "CreateToolhelp32Snapshot",
            "ERROR_NO_MORE_FILES",
            "GetCurrentProcess",
            "GetLastError",
            "INVALID_HANDLE_VALUE",
            "IsProcessInJob",
            "JOB_OBJECT_ASSIGN_PROCESS",
            "JOB_OBJECT_LIMIT_PROCESS_MEMORY",
            "JOBOBJECT_EXTENDED_LIMIT_INFORMATION",
            "JobObjectExtendedLimitInformation",
            "OpenProcess",
            "OpenThread",
            "PROCESS_ALL_ACCESS",
            "QueryInformationJobObject",
            "ResumeThread",
            "SetInformationJobObject",
            "TH32CS_SNAPTHREAD",
            "Thread32First",
            "Thread32Next",
            "THREAD_SUSPEND_RESUME",
        ])
        .write();

    let new = fs::read_to_string(&path).unwrap();
    similar_asserts::assert_eq!(old, new);
}
