use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use winapi::shared::minwindef::DWORD;
use winapi::um::lmwksta::{NetWkstaGetInfo, NetWkstaUserGetInfo};
use winapi::um::winnt::LPWSTR;

#[repr(C)]
struct WKSTA_INFO_100 {
    wki100_platform_id: DWORD,
    wki100_computername: LPWSTR,
    wki100_langroup: LPWSTR,
    wki100_ver_major: DWORD,
    wki100_ver_minor: DWORD,
}

#[repr(C)]
struct WKSTA_USER_INFO_1 {
    wkui1_username: LPWSTR,
}

extern "system" {
    fn NetApiBufferFree(Buffer: *mut u8) -> DWORD;
}

fn main() {
    unsafe {
        let mut p_wksta_info = null_mut();
        let mut p_user_info = null_mut();

        let wksta_status = NetWkstaGetInfo(null_mut(), 100, &mut p_wksta_info);
        let user_status = NetWkstaUserGetInfo(null_mut(), 1, &mut p_user_info);

        if wksta_status == 0 && user_status == 0 {
            let wksta_info = &*(p_wksta_info as *const WKSTA_INFO_100);
            let user_info = &*(p_user_info as *const WKSTA_USER_INFO_1);

            let hostname_os = OsString::from_wide_null(wksta_info.wki100_computername);
            let username_os = OsString::from_wide_null(user_info.wkui1_username);

            println!(
                "{}\\{}",
                hostname_os.to_string_lossy(),
                username_os.to_string_lossy()
            );

            NetApiBufferFree(p_wksta_info);
            NetApiBufferFree(p_user_info);
        } else {
            println!("Error: wksta_status={}, user_status={}", wksta_status, user_status);
        }
    }
}

trait FromWideNull {
    fn from_wide_null(s: LPWSTR) -> Self;
}

impl FromWideNull for OsString {
    fn from_wide_null(s: LPWSTR) -> Self {
        unsafe { Self::from_wide(std::slice::from_raw_parts(s, lstrlenw(s) as usize)) }
    }
}

unsafe fn lstrlenw(s: LPWSTR) -> usize {
    let mut len = 0;
    while *s.offset(len as isize) != 0 {
        len += 1;
    }
    len
}