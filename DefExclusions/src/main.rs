use std::ptr;
use regex::Regex;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStringExt, OsStrExt};
use winapi::um::winevt::{ EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtRender, EvtRenderEventXml};


fn main() {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational").encode_wide().chain(Some(0)).collect();
    let event_id = 5007;
    let pattern = Regex::new(r"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\[^\s]+").unwrap();
    let query_w: Vec<u16> = OsString::from(format!("*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID={})]]", event_id)).encode_wide().chain(Some(0)).collect();

    unsafe {
        let h_query = EvtQuery(ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return;
        }

        let mut events: [EVT_HANDLE; 10] = [ptr::null_mut(); 10];
        let mut returned = 0;

        while EvtNext(h_query, events.len() as u32, events.as_mut_ptr(), 0, 0, &mut returned) != 0 {
            for &event in &events[..returned as usize] {
                if event.is_null() {
                    continue;
                }

                let mut buffer_size: u32 = 0;
                EvtRender(ptr::null_mut(), event, EvtRenderEventXml, 0, ptr::null_mut(), &mut buffer_size, ptr::null_mut());
                let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

                if EvtRender(ptr::null_mut(), event, EvtRenderEventXml, buffer_size, buffer.as_mut_ptr() as *mut _, &mut buffer_size, ptr::null_mut()) == 0 {
                    eprintln!("Failed to render event");
                    EvtClose(event);
                    continue;
                }

                let message_str = OsString::from_wide(&buffer).to_string_lossy().into_owned();
                if message_str.contains("Exclusions") {
                    if let Some(caps) = pattern.captures(&message_str) {
                        println!("{}", &caps[0]);
                    }
                }

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }
}
