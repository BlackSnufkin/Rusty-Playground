use std::ffi::OsStr;
use std::ffi::{ CString};
use std::io::{Read};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::{Arc};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::shared::minwindef::ULONG;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::fileapi::ReadFile;
use winapi::um::fileapi::WriteFile;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::synchapi::CreateEventW;
use winapi::um::synchapi::SetEvent;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winbase::INFINITE;
use winapi::um::winbase::PIPE_ACCESS_DUPLEX;
use winapi::um::winbase::PIPE_READMODE_BYTE;
use winapi::um::winbase::PIPE_TYPE_BYTE;
use winapi::um::winbase::PIPE_WAIT;
use winapi::um::winnt::FILE_ATTRIBUTE_NORMAL;
use winapi::um::winnt::GENERIC_WRITE;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::PTP_CALLBACK_INSTANCE;
use winapi::um::winnt::PTP_IO;
use winapi::um::winnt::PTP_WORK;
use winapi::um::winnt::PVOID;
use winapi::um::winnt::TP_IO;
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::threadpoolapiset::CancelThreadpoolIo;
use winapi::um::threadpoolapiset::StartThreadpoolIo;
use winapi::um::threadpoolapiset::CloseThreadpoolIo;
use winapi::um::threadpoolapiset::CloseThreadpoolWork;
use winapi::um::threadpoolapiset::WaitForThreadpoolWorkCallbacks;
use winapi::um::threadpoolapiset::SubmitThreadpoolWork;
use winapi::um::threadpoolapiset::CreateThreadpoolWork;
use winapi::um::winnt::TP_CALLBACK_INSTANCE;
use winapi::um::threadpoolapiset::CreateThreadpoolIo;
use once_cell::sync::Lazy;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::winnt::TP_WORK;



struct LoadContext {
    dll_name: CString,
    ldr_load_dll: unsafe extern "system" fn(*const u16, u32, *const UNICODE_STRING, *mut HANDLE) -> u32,
}


struct UnloadContext {
    module_handle: HANDLE,
    ldr_unload_dll: unsafe extern "system" fn(HANDLE) -> u32,
}

// Function to be called by the threadpool work item for unloading the DLL
extern "system" fn unload_dll_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    _work: PTP_WORK,
) {
    let unload_context = unsafe { &*(context as *const UnloadContext) };

    let status = unsafe {
        (unload_context.ldr_unload_dll)(
            unload_context.module_handle,
        )
    };

    if status != 0 {
        eprintln!("LdrUnloadDll failed with status: {}", status);
    } else {
        println!("DLL unloaded successfully!");
    }
}


// Unsafe wrapper
struct UnsafeHandle(HANDLE);

unsafe impl Send for UnsafeHandle {}
unsafe impl Sync for UnsafeHandle {}


static WRITE_COMPLETE_EVENT: Lazy<Arc<UnsafeHandle>> = Lazy::new(|| {
    Arc::new(UnsafeHandle(unsafe {
        CreateEventW(null_mut(), TRUE, FALSE, null_mut())
    }))
});

extern "system" fn io_completion_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    _overlapped: *mut OVERLAPPED,
    _io_result: ULONG,
    _number_of_bytes_transferred: ULONG_PTR,
    _io: *mut TP_IO,
) {
    let load_context = unsafe { &*(context as *const LoadContext) };
    // Convert the CString to a wide string (UTF-16) and collect into a Vec<u16>
    let mut dll_name_wide: Vec<u16> = load_context.dll_name.to_str().unwrap().encode_utf16().collect();
    dll_name_wide.push(0); // Manually append null terminator

    let mut unicode_string = UNICODE_STRING {
        Length: ((dll_name_wide.len() - 1) * std::mem::size_of::<u16>()) as u16, // Length in bytes, excluding the null terminator
        MaximumLength: (dll_name_wide.len() * std::mem::size_of::<u16>()) as u16, // Maximum length in bytes, including the null terminator
        Buffer: dll_name_wide.as_ptr() as *mut _,
    };
    let mut module_handle: HANDLE = null_mut();

    let status = unsafe {
        (load_context.ldr_load_dll)(
            null_mut(), // Reserved, must be NULL
            0, // Flags, must be 0
            &mut unicode_string, // Module file name as UNICODE_STRING
            &mut module_handle // Receives the module handle
        )
    };

    if status != 0 {
        eprintln!("LdrLoadDll failed with status: {}", status);
    } else {
        println!("DLL loaded successfully!");
    }
}




extern "system" fn client_work_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    _context: PVOID,
    _work: PTP_WORK,
) {
    let pipe_name = r"\\.\pipe\MyPipe";
    let message = b"Hello from the pipe!";

    let pipe_name_utf16: Vec<u16> = OsStr::new(pipe_name).encode_wide().chain(once(0)).collect();
    let pipe = unsafe {
        CreateFileW(
            pipe_name_utf16.as_ptr(),
            GENERIC_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if pipe != INVALID_HANDLE_VALUE {
        let mut bytes_written = 0;
        let write_result = unsafe {
            WriteFile(
                pipe,
                message.as_ptr() as *const winapi::ctypes::c_void,
                message.len() as DWORD,
                &mut bytes_written,
                null_mut(),
            )
        };
        if write_result == 0 {
            eprintln!("Client WriteFile failed: {}", std::io::Error::last_os_error());
        } else {
            println!("Client wrote to pipe");
        }

        unsafe { CloseHandle(pipe) };
    } else {
        eprintln!("Client failed to connect to pipe: {}", std::io::Error::last_os_error());
    }

    unsafe { SetEvent(WRITE_COMPLETE_EVENT.0 as *mut winapi::ctypes::c_void) };
}


extern "system" fn io_completion_callback_wrapper(
    instance: *mut TP_CALLBACK_INSTANCE,
    context: *mut winapi::ctypes::c_void,
    overlapped: *mut winapi::ctypes::c_void,
    io_result: u32,
    number_of_bytes_transferred: usize,
    io: *mut TP_IO,
) {
    // Cast `overlapped` back to the expected type for `io_completion_callback`
    let overlapped_casted = overlapped as *mut OVERLAPPED;

    // Call the original callback with the correct argument types
    io_completion_callback(
        instance,
        context,
        overlapped_casted,
        io_result,
        number_of_bytes_transferred,
        io,
    );
}


fn start_read(pipe: *mut c_void  , tp_io: PTP_IO, overlapped: &mut OVERLAPPED, buffer: &mut [u8]) {
    let mut bytes_read = 0;
    unsafe {
        StartThreadpoolIo(tp_io);
        if ReadFile(
            pipe as *mut c_void ,
            buffer.as_mut_ptr() as *mut c_void, // Corrected c_void usage
            buffer.len() as u32,
            &mut bytes_read,
            overlapped,
        ) == 0
            && GetLastError() != ERROR_IO_PENDING
        {
            eprintln!("ReadFile failed: {}", std::io::Error::last_os_error());
            CancelThreadpoolIo(tp_io);
        }
    }
}


fn create_load_context() -> LoadContext {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    let ldr_load_dll_sym = unsafe { GetProcAddress(ntdll, b"LdrLoadDll\0".as_ptr() as *const i8) };
    if ldr_load_dll_sym.is_null() {
        panic!("Failed to find LdrLoadDll");
    }

    let ldr_load_dll: unsafe extern "system" fn(
        *const u16,
        u32,
        *const UNICODE_STRING,
        *mut HANDLE,
    ) -> u32 = unsafe { std::mem::transmute(ldr_load_dll_sym) };

    LoadContext {
        dll_name: CString::new("mshtml.dll").unwrap(),
        ldr_load_dll,
    }
}

fn create_named_pipe() -> HANDLE {
    let pipe_name = r"\\.\pipe\MyPipe";
    let pipe_name_utf16: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(once(0))
        .collect();

    let pipe = unsafe {
        CreateNamedPipeW(
            pipe_name_utf16.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            null_mut(),
        )
    };

    if pipe == INVALID_HANDLE_VALUE {
        eprintln!("Failed to create named pipe: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    pipe
}

fn create_overlapped_event() -> OVERLAPPED {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };

    if overlapped.hEvent == null_mut() {
        eprintln!("Failed to create event");
        std::process::exit(1);
    }

    overlapped
}





fn associate_pipe_with_thread_pool(pipe: HANDLE, load_context: &LoadContext) -> *mut TP_IO {
    let tp_io = unsafe {
        CreateThreadpoolIo(
            pipe,
            Some(io_completion_callback_wrapper as unsafe extern "system" fn(*mut TP_CALLBACK_INSTANCE, *mut c_void, *mut c_void, u32, usize, *mut TP_IO)),
            load_context as *const _ as *mut c_void,
            null_mut(),
        )
    };

    if tp_io.is_null() {
        eprintln!("Failed to associate pipe with thread pool");
        std::process::exit(1);
    }

    tp_io
}

fn create_client_work_threadpool() -> *mut TP_WORK {
    let client_work = unsafe {
        CreateThreadpoolWork(
            Some(client_work_callback),
            null_mut(),
            null_mut(),
        )
    };

    if client_work.is_null() {
        eprintln!("Failed to create threadpool work item");
        std::process::exit(1);
    }

    client_work
}

fn submit_client_work(client_work: *mut TP_WORK) {
    unsafe { SubmitThreadpoolWork(client_work) };
}

fn wait_for_write_complete_event() {
    unsafe { WaitForSingleObject((**WRITE_COMPLETE_EVENT).0, INFINITE); };
}

fn wait_for_single_object(event: HANDLE) {
    unsafe { WaitForSingleObject(event as *mut _, INFINITE) };
}

fn wait_for_threadpool_work_callbacks(client_work: *mut TP_WORK) {
    unsafe { WaitForThreadpoolWorkCallbacks(client_work, 0) };
}

fn cleanup_resources(tp_io: *mut TP_IO, event: HANDLE, pipe: HANDLE, client_work: *mut TP_WORK) {
    unsafe {
        CloseThreadpoolIo(tp_io);
        CloseHandle(event);
        CloseHandle(pipe);
        CloseThreadpoolWork(client_work);
    }
}

fn wait_for_user_input() {
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input).unwrap();
}

fn create_unload_context() -> UnloadContext {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    let ldr_unload_dll_sym = unsafe { GetProcAddress(ntdll, b"LdrUnloadDll\0".as_ptr() as *const i8) };
    if ldr_unload_dll_sym.is_null() {
        panic!("Failed to find LdrUnloadDll");
    }

    let ldr_unload_dll: unsafe extern "system" fn(HANDLE) -> u32 = unsafe { std::mem::transmute(ldr_unload_dll_sym) };
    
    let module_handle = unsafe { GetModuleHandleA(b"mshtml.dll\0".as_ptr() as *const i8) };

    UnloadContext {
        module_handle: module_handle as *mut c_void,
        ldr_unload_dll,
    }
}

fn create_unload_dll_threadpool(unload_context: &UnloadContext) -> *mut TP_WORK {
    let unload_work = unsafe {
        CreateThreadpoolWork(
            Some(unload_dll_callback),
            unload_context as *const _ as *mut c_void,
            null_mut(),
        )
    };

    if unload_work.is_null() {
        eprintln!("Failed to create threadpool work item for DLL unload");
        std::process::exit(1);
    }

    unload_work
}

fn submit_unload_work(unload_work: *mut TP_WORK) {
    unsafe { SubmitThreadpoolWork(unload_work) };
}

fn wait_for_unload_work_callbacks(unload_work: *mut TP_WORK) {
    unsafe { WaitForThreadpoolWorkCallbacks(unload_work, 0) };
    unsafe { CloseThreadpoolWork(unload_work) };
}


fn main() {
    let load_context = create_load_context();
    let pipe = create_named_pipe();
    let mut overlapped = create_overlapped_event();
    let tp_io = associate_pipe_with_thread_pool(pipe, &load_context);
    let client_work = create_client_work_threadpool();

    submit_client_work(client_work);
    wait_for_write_complete_event();

    let mut buffer = [0u8; 128];
    start_read(pipe, tp_io, &mut overlapped, &mut buffer);
    println!("Pipe buffer: {}", String::from_utf8_lossy(&buffer));

    wait_for_single_object(overlapped.hEvent);
    wait_for_threadpool_work_callbacks(client_work);

    cleanup_resources(tp_io, overlapped.hEvent, pipe, client_work);

    println!("mshtml.dll should be loaded! Input any key to continue...");
    wait_for_user_input();

    let unload_context = create_unload_context();
    let unload_work = create_unload_dll_threadpool(&unload_context);

    submit_unload_work(unload_work);
    wait_for_unload_work_callbacks(unload_work);

    println!("DLL should be unloaded! Input any key to exit...");    wait_for_user_input();
}

