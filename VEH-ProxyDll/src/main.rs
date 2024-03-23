
use std::ffi::{CString};

use std::ptr;
use winapi::shared::minwindef::{BOOL, HMODULE};
use winapi::shared::ntdef::LONG;

use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::shared::ntdef::PVOID;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READ;
use winapi::um::winnt::PAGE_GUARD;
use winapi::um::winnt::PEXCEPTION_POINTERS;
use winapi::vc::excpt::EXCEPTION_CONTINUE_EXECUTION;
use winapi::vc::excpt::EXCEPTION_CONTINUE_SEARCH;
use winapi::um::winnt::LPCSTR;

use winapi::um::errhandlingapi::AddVectoredExceptionHandler;


use winapi::um::errhandlingapi::RemoveVectoredExceptionHandler;



type FnCheckGadget = unsafe extern "system" fn(PVOID) -> BOOL;


static MODULE_NAME: &str = "mshtml.dll";

unsafe fn find_gadget(p_module: PVOID, callback_check: FnCheckGadget) -> PVOID {
    let mut i = 0;
    loop {
        let addr = (p_module as usize + i) as PVOID;
        if callback_check(addr) != 0 {
            return addr;
        }
        i += 1;
    }
}

unsafe extern "system" fn fn_gadget_jmp_rax(p_addr: PVOID) -> BOOL {
    let addr = p_addr as *const u8;
    if *addr == 0xFF && *addr.offset(1) == 0xE0 {
        1
    } else {
        0
    }
}


unsafe extern "system" fn vectored_exception_handler(exception_info: PEXCEPTION_POINTERS) -> LONG {
    
    if (*(*exception_info).ExceptionRecord).ExceptionCode == 0x80000001 {
        
        let load_library_addr = GetProcAddress(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as LPCSTR), b"LoadLibraryA\0".as_ptr() as LPCSTR);
        
        (*(*exception_info).ContextRecord).Rax = load_library_addr as u64;
        
        let p_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as LPCSTR);
        let p_jmp_rax_gadget = find_gadget(p_ntdll as PVOID, fn_gadget_jmp_rax);
        (*(*exception_info).ContextRecord).Rip = p_jmp_rax_gadget as u64;
        
        let module_name = MODULE_NAME.as_ptr() as LPCSTR;
        (*(*exception_info).ContextRecord).Rcx = module_name as u64;
        
        EXCEPTION_CONTINUE_EXECUTION 
    } else {
        
        EXCEPTION_CONTINUE_SEARCH
    }
}

fn proxied_load_library_a(lib_name: LPCSTR) -> HMODULE {
    
    let sleep_addr = winapi::um::synchapi::Sleep as PVOID;
    
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_exception_handler)) };
    if handler.is_null() {
        eprintln!("Failed to install Vectored Exception Handler");
        return ptr::null_mut();
    }
    
    let mut old_protection = 0;
    unsafe {
        VirtualProtect(sleep_addr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &mut old_protection);
        
        winapi::um::synchapi::Sleep(0);
    }
    
    let module_handle = unsafe { GetModuleHandleA(lib_name) };
    
    unsafe { RemoveVectoredExceptionHandler(handler) };
    module_handle
}

fn main() {
    let module_name = CString::new(MODULE_NAME).unwrap();
    let dll_handle = proxied_load_library_a(module_name.as_ptr());
    if !dll_handle.is_null() {
        println!("{} loaded successfully. Address: {:?}", MODULE_NAME, dll_handle);
    } else {
        println!("Failed to load {}", MODULE_NAME);
    }
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read input");
}
