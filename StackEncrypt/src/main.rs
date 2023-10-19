#![allow(non_snake_case, dead_code, unused_imports,unused_variables)]

use std::mem;
use std::ptr::NonNull;
use std::arch::asm;
use winapi::shared::ntdef::{NTSTATUS, PVOID, HANDLE, ULONG};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION};
use winapi::shared::minwindef::DWORD;
use rand::prelude::SliceRandom;


extern "system" {
    // NT syscalls
    fn NtCreateThreadEx(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: ULONG,
        ObjectAttributes: PVOID,
        ProcessHandle: HANDLE,
        StartRoutine: PVOID,
        Argument: PVOID,
        CreateSuspended: DWORD,
        ZeroBits: ULONG,
        StackSize: ULONG,
        MaximumStackSize: PVOID,
        AttributeList: PVOID,
    ) -> NTSTATUS;
    fn NtDelayExecution(Alertable: bool, DelayInterval: *const i64) -> NTSTATUS;
    fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: ULONG,
        MemoryInformation: PVOID,
        MemoryInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    fn NtResumeThread(ThreadHandle: HANDLE, SuspendCount: *mut ULONG) -> NTSTATUS;
    fn NtSuspendThread(ThreadHandle: HANDLE, PreviousSuspendCount: *mut ULONG) -> NTSTATUS;
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
    fn NtWaitForSingleObject(
        Handle: HANDLE,
        Alertable: bool,
        Timeout: *const i64
    ) -> NTSTATUS;

}


const DELAY_MULTIPLIER: i64 = 10_000;
const STACK_OFFSET: isize = 8192;


fn shuffle_stack(p: *mut u8, stack_size: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..stack_size).collect();
    order.shuffle(&mut rand::thread_rng()); // Using rand crate for shuffling
    
    let mut shuffled_stack = vec![0u8; stack_size];
    for (i, &pos) in order.iter().enumerate() {
        unsafe {
            shuffled_stack[i] = *p.add(pos);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = shuffled_stack[i];
        }
    }
    
    order
}

fn restore_stack(p: *mut u8, stack_size: usize, order: Vec<usize>) {
    let mut original_stack = vec![0u8; stack_size];
    for i in 0..stack_size {
        unsafe {
            original_stack[order[i]] = *p.add(i);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = original_stack[i];
        }
    }
}




fn xor_encrypt(p: *mut u8, stack_size: usize, key: &[u8]) {
    let key_length = key.len();
    for i in 0..stack_size {
        unsafe {
            *p.add(i) ^= key[i % key_length];
        }
    }
}

unsafe extern "system" fn encrypt_thread(duration: PVOID) -> DWORD {
    println!("[+] Entered encrypt_thread");

    let ms = *(duration as *const u64);
    println!("[+] Sleep duration: {}", ms);

    let delay_interval = -(DELAY_MULTIPLIER * ms as i64);
    println!("[+] Delay interval: {}", delay_interval);

    let key = b"It2H@Qp3Xe*sxdc#KA8)dbMtI5Q7&FK";

    let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
    NtQueryVirtualMemory(
        -1isize as HANDLE,
        duration,
        0,
        &mut mbi as *mut _ as PVOID,
        mem::size_of::<MEMORY_BASIC_INFORMATION>() as ULONG,
        std::ptr::null_mut(),
    );

    let stack_region = (mbi.BaseAddress as isize - STACK_OFFSET) as *mut u8;
    let stack_base = (stack_region as isize + mbi.RegionSize as isize + STACK_OFFSET) as *mut u8;
    let stack_size = stack_base as usize - duration as *mut u8 as usize;
    println!("[+] Calculated stack region and base");

    // 1. Snapshot the current state of the stack
    let _stack_snapshot: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();
    println!("[+] Stack snapshot taken");



    // 2. Shuffle the stack
    let order = shuffle_stack(stack_region, stack_size);
    let _stack_after_shuffle: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();
    println!("[+] Stack shuffled");



    // 3. Encrypt the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_encryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();
    println!("[+] First encryption pass done");



    let status = NtDelayExecution(false, &delay_interval);
    if status < 0 {
        eprintln!("[-] NtDelayExecution failed with status: {:#X}", status);
    } else {
        println!("[+] Sleep done");
    }

    // 4. Decrypt the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_decryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();
    println!("[+] Second encryption pass done");



    // 5. Restore the original order of the stack
    restore_stack(stack_region, stack_size, order);
    let _stack_after_restore: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();
    println!("[+] Stack order restored");


    0
}



fn encrypted_sleep(ms: u64) {
    println!("[+] Entered encrypted_sleep function");

    let _rsp = {
        let rsp: *const u8;
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp);
            println!("[+] Retrieved rsp: {:p}", rsp);
        }
        NonNull::new(rsp as *mut u8).expect("Failed to get rsp")
    };

    let mut encrypt_thread_handle: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        NtCreateThreadEx(
            &mut encrypt_thread_handle,
            0x001F03FF,
            std::ptr::null_mut(),
            -1isize as HANDLE,
            encrypt_thread as *mut _,
            &ms as *const _ as PVOID,
            1,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if status < 0 {
        eprintln!("[-] Failed to create thread {:#X}", status);
        return;
    }
    println!("[+] Thread created successfully");

    unsafe { NtResumeThread(encrypt_thread_handle, std::ptr::null_mut()) };
    println!("[+] Resumed the thread");
    
    // Wait for the thread to complete its execution
    unsafe {NtWaitForSingleObject(encrypt_thread_handle, false, std::ptr::null())};
    
    unsafe { NtSuspendThread(encrypt_thread_handle, std::ptr::null_mut()) };
    println!("[+] Suspended the thread");
    
    unsafe{NtClose(encrypt_thread_handle)};
}

fn main() {
    println!("[+] Starting main function");
    encrypted_sleep(5000);
    println!("[+] Finished main function");
}