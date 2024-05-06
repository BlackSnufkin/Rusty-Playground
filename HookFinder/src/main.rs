use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::PEB_LDR_DATA;
use ntapi::winapi_local::um::winnt::__readgsqword;
use std::ffi::OsString;
use std::ffi::{CStr};
use std::mem;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::slice;
use winapi::shared::minwindef::{DWORD, WORD};
use winapi::shared::ntdef::{LIST_ENTRY, PVOID};
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_DOS_SIGNATURE;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use winapi::um::winnt::IMAGE_NT_SIGNATURE;


static mut H_NTDLL: PVOID = ptr::null_mut();


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


fn hook_finder() -> i32 {
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


fn main() {
    unsafe {H_NTDLL = get_nt()};
    println!("NTDLL base address and required functions initialized.");

    if hook_finder() != 0 {
        println!("Hooking check failed.");
        return;
    }
}