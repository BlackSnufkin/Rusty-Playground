#![allow(non_snake_case, non_camel_case_types, unused_imports)]
extern crate winapi;
use std::ffi::{OsStr, CString};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use winapi::um::fileapi::*;
use winapi::um::handleapi::*;
use winapi::um::winnt::*;
use std::io::Result;
use rand::Rng;
use winapi::shared::minwindef::DWORD;
use winapi::um::minwinbase::FileRenameInfo;
use winapi::um::minwinbase::FileDispositionInfo;
use std::time::Duration;
use winapi::um::winuser::{MessageBoxA, MB_OK};
use md5::{Md5, Digest};

fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn get_original_with_random_appended(random_bytes_size: usize) -> std::io::Result<Vec<u8>> {
    let current_exe_path = std::env::current_exe()?;
    let original_bytes = fs::read(&current_exe_path)?;
    let mut rng = rand::thread_rng();
    let mut random_bytes = vec![0u8; random_bytes_size];
    rng.fill(&mut random_bytes[..]);
    let mut combined = Vec::with_capacity(original_bytes.len() + random_bytes.len());
    combined.extend_from_slice(&original_bytes);
    combined.extend_from_slice(&random_bytes);
    Ok(combined)
}

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
        .collect();
    let file_name_length = (new_name_wide.len() * std::mem::size_of::<u16>()) as DWORD;
    
    let mut buffer = vec![0u8; std::mem::size_of::<FILE_RENAME_INFO>() + new_name_wide.len() * std::mem::size_of::<u16>()];
    let info = unsafe {
        &mut *(buffer.as_mut_ptr() as *mut FILE_RENAME_INFO)
    };
    info.ReplaceIfExists = 0;
    info.RootDirectory = null_mut();
    info.FileNameLength = file_name_length as DWORD;
    
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

fn main() -> std::io::Result<()> {
    // Calculate hash of current exe
    let exe_path = std::env::current_exe()?;
    let current_bytes = fs::read(&exe_path)?;
    let hash = calculate_hash(&current_bytes);

    // Show hash in message box
    let title = CString::new("File Hash").unwrap();
    let content = CString::new(format!("Current File Hash: {}", hash)).unwrap();
    unsafe {
        MessageBoxA(
            null_mut(),
            content.as_ptr(),
            title.as_ptr(),
            MB_OK
        );
    }

    // 1. Get the original file with random bytes appended
    let modified_bytes = get_original_with_random_appended(1024)?;
    
    // 2. Get current executable path and prepare new path
    let exe_path_str = exe_path.to_str().expect("Path to string conversion failed");
    
    // 3. Self delete process
    println!("\n[+] Starting self-delete process");
    
    let handle = open_handle(exe_path_str)?;
    println!("[+] File handle opened successfully");
    println!("[*] Handle value: {:?}", handle);
    
    rename_handle(handle)?;
    println!("[+] File stream renamed to :BlackSnufkin");
    unsafe { CloseHandle(handle); }
    println!("[*] Handle closed");
    
    println!("[*] Waiting 500ms before deletion...");
    std::thread::sleep(Duration::from_millis(500));
    
    let handle = open_handle(exe_path_str)?;
    println!("[+] Reopened file handle for deletion");
    println!("[*] Handle value: {:?}", handle);
    
    deposite_handle(handle)?;
    println!("[+] File marked for deletion");
    unsafe { CloseHandle(handle); }
    println!("[*] Handle closed\n");
    
    // 4. Save the modified copy
    let file_name = exe_path.file_stem().unwrap().to_str().unwrap();
    let save_path = Path::new(".").join(format!("{}.exe", file_name));
    fs::write(&save_path, modified_bytes)?;
    
    Ok(())
}