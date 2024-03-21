use std::collections::HashSet;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::winuser::{CF_HDROP, CF_TEXT, GetClipboardData, OpenClipboard, CloseClipboard};
use std::ffi::OsString;
use winapi::um::shellapi::HDROP;
use winapi::um::shellapi::DragQueryFileA;

fn handle_text_clipboard(log_file: &mut File, last_clipboard_text: &mut String) -> Result<(), Error> {
    let hglb = unsafe { GetClipboardData(CF_TEXT) };

    if !hglb.is_null() {
        let clipboard_content = unsafe { get_clipboard_text(hglb) };

        if clipboard_content != *last_clipboard_text {
            println!("New text found in clipboard: {}", clipboard_content);
            writeln!(log_file, "{}", clipboard_content)?;
            println!("Text appended to log file.");
            *last_clipboard_text = clipboard_content;
        }
    }

    Ok(())
}

fn handle_file_clipboard(
    output_dir: &Path,
    last_copied_files: &mut HashSet<PathBuf>,
) -> Result<(), Error> {
    let hglb_files = unsafe { GetClipboardData(CF_HDROP) } as HDROP;

    if !hglb_files.is_null() {
        let count = unsafe { DragQueryFileA(hglb_files, 0xFFFFFFFF, std::ptr::null_mut(), 0) };

        if count > 0 {
            let mut new_files_copied = false;

            for i in 0..count {
                let mut buffer = [0i8; MAX_PATH as usize];
                let len =
                    unsafe { DragQueryFileA(hglb_files, i, buffer.as_mut_ptr(), MAX_PATH as u32) };

                if len > 0 {
                    let path = unsafe {
                        let path_bytes: Vec<u8> = buffer[..len as usize]
                            .iter()
                            .map(|b| *b as u8)
                            .collect();

                        let path = if let Some(terminator_pos) = path_bytes.iter().position(|&b| b == 0) {
                            std::ffi::CStr::from_bytes_with_nul(&path_bytes[..terminator_pos])
                                .unwrap()
                                .to_string_lossy()
                                .into_owned()
                        } else {
                            String::from_utf8_lossy(&path_bytes).into_owned()
                        };

                        PathBuf::from(path)
                    };

                    if last_copied_files.insert(path.clone()) {
                        let file_name: OsString = path.file_name().unwrap().into();
                        let output_path = output_dir.join(file_name);

                        if let Err(err) = std::fs::copy(&path, &output_path) {
                            println!("Failed to copy '{}': {}", path.display(), err);
                        } else {
                            println!(
                                "Copied new file '{}' to '{}'",
                                path.display(),
                                output_dir.display()
                            );
                            new_files_copied = true;
                        }
                    }
                }
            }

            if !new_files_copied {
                //println!("No new files to copy.");
            }
        }
    }

    Ok(())
}

unsafe fn get_clipboard_text<'a>(hglb: *mut winapi::ctypes::c_void) -> String {
    let p = std::ffi::CStr::from_ptr(hglb as *const i8);
    p.to_string_lossy().into_owned()
}


fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Usage: clipboard_monitor <log_file_path> <output_dir>",
        ));
    }

    let log_path = PathBuf::from(&args[1]);
    let output_dir = PathBuf::from(&args[2]);

    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&log_path)?;

    let mut last_clipboard_text = String::new();
    let mut last_copied_files: HashSet<PathBuf> = HashSet::new();

    println!(
        "Monitoring the clipboard for changes. Logging to '{}'. Output directory: '{}'",
        log_path.display(),
        output_dir.display()
    );

    loop {
        if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
            if let Err(err) = handle_text_clipboard(&mut log_file, &mut last_clipboard_text) {
                println!("Error handling text clipboard: {}", err);
            }

            if let Err(err) = handle_file_clipboard(&output_dir, &mut last_copied_files) {
                println!("Error handling file clipboard: {}", err);
            }

            unsafe { CloseClipboard() };
        } else {
            println!("Failed to open clipboard.");
        }

        thread::sleep(Duration::from_millis(100));
    }
}