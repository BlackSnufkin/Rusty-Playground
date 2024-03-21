
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

// Module to load, change to your liking
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

// Exception handler function
unsafe extern "system" fn vectored_exception_handler(exception_info: PEXCEPTION_POINTERS) -> LONG {
    // Check for STATUS_GUARD_PAGE_VIOLATION
    if (*(*exception_info).ExceptionRecord).ExceptionCode == 0x80000001 {
        // Get the address of "LoadLibraryA"
        let load_library_addr = GetProcAddress(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as LPCSTR), b"LoadLibraryA\0".as_ptr() as LPCSTR);
        // Set RAX register to the address of "LoadLibraryA"
        (*(*exception_info).ContextRecord).Rax = load_library_addr as u64;
        // Jump to RAX via ROP Gadget
        let p_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as LPCSTR);
        let p_jmp_rax_gadget = find_gadget(p_ntdll as PVOID, fn_gadget_jmp_rax);
        (*(*exception_info).ContextRecord).Rip = p_jmp_rax_gadget as u64;
        // RCX holds the argument (library name)
        let module_name = MODULE_NAME.as_ptr() as LPCSTR;
        (*(*exception_info).ContextRecord).Rcx = module_name as u64;
        // Resume execution
        EXCEPTION_CONTINUE_EXECUTION // Continue to the next instruction
    } else {
        // Continue searching for other exception handlers
        EXCEPTION_CONTINUE_SEARCH
    }
}

fn proxied_load_library_a(lib_name: LPCSTR) -> HMODULE {
    // Just something to get its address to trigger the VEH
    let sleep_addr = winapi::um::synchapi::Sleep as PVOID;
    // Install the Vectored Exception Handler
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_exception_handler)) };
    if handler.is_null() {
        eprintln!("Failed to install Vectored Exception Handler");
        return ptr::null_mut();
    }
    // Triggering the VEH by setting page to PAGE_GUARD
    let mut old_protection = 0;
    unsafe {
        VirtualProtect(sleep_addr, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &mut old_protection);
        // Trigger the exception by calling Sleep
        winapi::um::synchapi::Sleep(0);
    }
    // The module should now be loaded, so retrieve its base address
    let module_handle = unsafe { GetModuleHandleA(lib_name) };
    // Remove the Vectored Exception Handler
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