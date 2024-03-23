use std::io::{self, BufRead};
use std::mem;
use std::ptr;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::heapapi::{GetProcessHeap, GetProcessHeaps, HeapAlloc, HeapCreate, HeapDestroy, HeapFree, HeapWalk};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread};
use winapi::um::synchapi::Sleep;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32};
use winapi::um::winnt::{HANDLE, THREAD_SUSPEND_RESUME};
use winapi::um::minwinbase::PROCESS_HEAP_ENTRY_BUSY;
use winapi::um::minwinbase::PROCESS_HEAP_ENTRY;

const KEY_BUF: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF];

fn roll_xor(pkey: &[u8; 16], p: *mut u8, cb: usize) {
    for i in 0..cb {
        unsafe {
            *p.offset(i as isize) ^= pkey[i % 16];
        }
    }
}

fn heap_enc_sleep(ms: DWORD) {
    let num_heaps = unsafe { GetProcessHeaps(0, ptr::null_mut()) };
    let mut heap_handles_on_heap = Vec::with_capacity(num_heaps as usize);
    unsafe {
        heap_handles_on_heap.set_len(num_heaps as usize);
        GetProcessHeaps(num_heaps, heap_handles_on_heap.as_mut_ptr());
    }

    let h_heap = unsafe { HeapCreate(0, 0, 0) };

    let p_heaps = unsafe {
        HeapAlloc(
            h_heap,
            0,
            ((mem::size_of::<HANDLE>() * num_heaps as usize) as u64).try_into().unwrap(),
        ) as *mut HANDLE
    };
    unsafe {
        ptr::copy_nonoverlapping(heap_handles_on_heap.as_ptr(), p_heaps, num_heaps as usize);
        ptr::write_bytes(heap_handles_on_heap.as_mut_ptr(), 0, num_heaps as usize);
    }

    let p_heap_entry = unsafe {
        HeapAlloc(
            h_heap,
            0,
            (mem::size_of::<PROCESS_HEAP_ENTRY>() as u64).try_into().unwrap(),
        ) as *mut PROCESS_HEAP_ENTRY
    };

    // Heap XOR
    for i in 0..num_heaps {
        unsafe {
            ptr::write_bytes(p_heap_entry, 0, 1);
            while HeapWalk(*p_heaps.offset(i as isize), p_heap_entry) != 0 {
                if (*p_heap_entry).wFlags & PROCESS_HEAP_ENTRY_BUSY != 0 {
                    roll_xor(
                        &KEY_BUF,
                        (*p_heap_entry).lpData as *mut u8,
                        (*p_heap_entry).cbData as usize,
                    );
                }
            }
        }
    }

    unsafe {
        Sleep(ms);
    }

    // Heap XOR
    for i in 0..num_heaps {
        unsafe {
            ptr::write_bytes(p_heap_entry, 0, 1);
            while HeapWalk(*p_heaps.offset(i as isize), p_heap_entry) != 0 {
                if (*p_heap_entry).wFlags & PROCESS_HEAP_ENTRY_BUSY != 0 {
                    roll_xor(
                        &KEY_BUF,
                        (*p_heap_entry).lpData as *mut u8,
                        (*p_heap_entry).cbData as usize,
                    );
                }
            }
        }
    }

    unsafe {
        HeapFree(h_heap, 0, p_heaps as LPVOID);
        HeapFree(h_heap, 0, p_heap_entry as LPVOID);
        HeapDestroy(h_heap);
    }
}

fn do_suspend_threads(target_process_id: DWORD, target_thread_id: DWORD) {
    let h_thread_snap = unsafe { CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPTHREAD, 0) };
    if h_thread_snap == INVALID_HANDLE_VALUE {
        return;
    }

    let mut thread_entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    let mut cont_thread_snap_walk = unsafe { Thread32First(h_thread_snap, &mut thread_entry) };

    while cont_thread_snap_walk != 0 {
        if thread_entry.dwSize >= (4 * mem::size_of::<DWORD>()) as DWORD {
            if thread_entry.th32OwnerProcessID == target_process_id
                && thread_entry.th32ThreadID != target_thread_id
            {
                let h_thread = unsafe {
                    OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID)
                };
                if h_thread != std::ptr::null_mut() {
                    #[cfg(debug_assertions)]
                    println!("Suspending thread {}", thread_entry.th32ThreadID);
                    unsafe {
                        SuspendThread(h_thread);
                        CloseHandle(h_thread);
                    }
                }
            }
        }

        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as DWORD;
        cont_thread_snap_walk = unsafe { Thread32Next(h_thread_snap, &mut thread_entry) };
    }

    unsafe {
        CloseHandle(h_thread_snap);
    }
}

fn do_resume_threads(target_process_id: DWORD, target_thread_id: DWORD) {
    let h_thread_snap = unsafe { CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPTHREAD, 0) };
    if h_thread_snap == INVALID_HANDLE_VALUE {
        return;
    }

    let mut thread_entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    let mut cont_thread_snap_walk = unsafe { Thread32First(h_thread_snap, &mut thread_entry) };

    while cont_thread_snap_walk != 0 {
        if thread_entry.dwSize >= (4 * mem::size_of::<DWORD>()) as DWORD {
            if thread_entry.th32OwnerProcessID == target_process_id
                && thread_entry.th32ThreadID != target_thread_id
            {
                let h_thread = unsafe {
                    OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID)
                };
                if h_thread != std::ptr::null_mut() {
                    #[cfg(debug_assertions)]
                    println!("Resuming thread {}", thread_entry.th32ThreadID);
                    unsafe {
                        ResumeThread(h_thread);
                        CloseHandle(h_thread);
                    }
                }
            }
        }

        thread_entry.dwSize = mem::size_of::<THREADENTRY32>() as DWORD;
        cont_thread_snap_walk = unsafe { Thread32Next(h_thread_snap, &mut thread_entry) };
    }

    unsafe {
        CloseHandle(h_thread_snap);
    }
}

fn main() {
    loop {
        println!("Sleeping for 20 seconds on key ->");
        let _ = io::stdin().lock().lines().next();

        let current_process_id = unsafe { GetCurrentProcessId() };
        let current_thread_id = unsafe { GetCurrentThreadId() };

        do_suspend_threads(current_process_id, current_thread_id);
        heap_enc_sleep(20 * 1000);
        do_resume_threads(current_process_id, current_thread_id);
    }
}