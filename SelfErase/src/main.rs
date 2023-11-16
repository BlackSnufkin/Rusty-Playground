#![allow(non_snake_case,non_camel_case_types, unused_imports)]

extern crate winapi;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::fileapi::*;
use winapi::um::handleapi::*;
use winapi::um::winnt::*;
use std::io::Result;
use winapi::shared::minwindef::DWORD;
use winapi::um::minwinbase::FileRenameInfo;
use winapi::um::minwinbase::FileDispositionInfo;
use std::time::Duration;

fn open_handle(path: &str) -> Result<HANDLE> {
    let path_wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            DELETE,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}

fn rename_handle(handle: HANDLE) -> Result<()> {
    let new_name = ":BlackSnufkin";
    let new_name_wide: Vec<u16> = OsStr::new(new_name)
        .encode_wide()
        .collect(); // No need for null terminator, Rust Vec ensures null termination

    let file_name_length = (new_name_wide.len() * std::mem::size_of::<u16>()) as DWORD;

    // Creating a buffer to hold FILE_RENAME_INFO + new name
    let mut buffer = vec![0u8; std::mem::size_of::<FILE_RENAME_INFO>() + new_name_wide.len() * std::mem::size_of::<u16>()];
    let info = unsafe {
        &mut *(buffer.as_mut_ptr() as *mut FILE_RENAME_INFO)
    };

    info.ReplaceIfExists = 0;
    info.RootDirectory = null_mut();
    info.FileNameLength = file_name_length as DWORD;

    // Copying the new name into the buffer right after FILE_RENAME_INFO
    unsafe {
        std::ptr::copy_nonoverlapping(
            new_name_wide.as_ptr(),
            info.FileName.as_mut_ptr(),
            new_name_wide.len(),
        );

        if SetFileInformationByHandle(
            handle,
            FileRenameInfo,
            buffer.as_ptr() as *mut _,
            buffer.len() as DWORD,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}


fn deposite_handle(handle: HANDLE) -> Result<()> {
    let mut info = FILE_DISPOSITION_INFO { DeleteFile: 1 };

    unsafe {
        if SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as DWORD,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn main() {
    let exe_path = std::env::current_exe().expect("Failed to get current executable path");
    let exe_path_str = exe_path.to_str().expect("Path to string conversion failed");

    let handle = open_handle(exe_path_str).expect("Failed to open file handle");
    println!("[*] Open file handler");
    println!("[*] Handle: {:?}", handle);

    rename_handle(handle).expect("Failed to rename file handle");
    println!("[*] Rename file");

    unsafe { CloseHandle(handle); }
    println!("[*] Close file handler");
    std::thread::sleep(Duration::from_millis(500));
    let handle = open_handle(exe_path_str).expect("Failed to open file handle again");
    println!("[*] Open file handler");
    println!("[*] Handle: {:?}", handle);

    deposite_handle(handle).expect("Failed to mark file for deletion");
    println!("[*] Deposite file handle");

    unsafe { CloseHandle(handle); }
    println!("[*] Close file handler");
    
}
