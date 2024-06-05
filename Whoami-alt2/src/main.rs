use std::ffi::OsString;
use std::io::Error;
use std::iter::once;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use std::vec::Vec;
use winapi::um::winnetwk::WNetGetUserW;
use winapi::shared::lmcons::UNLEN;

fn main() -> Result<(), Error> {
    let buffer_length = UNLEN as u32 + 1;
    let mut user_name: Vec<u16> = vec![0; buffer_length as usize];
    let mut buffer_length = buffer_length;

    let result = unsafe { WNetGetUserW(null_mut(), user_name.as_mut_ptr(), &mut buffer_length) };

    if result == 0 { // NO_ERROR is 0
        let user_name = OsString::from_wide(&user_name[..(buffer_length as usize) - 1]);
        println!("Current user name: {}", user_name.to_string_lossy());
    } else {
        println!("WNetGetUser failed. Error: {}", result);
    }

    Ok(())
}
