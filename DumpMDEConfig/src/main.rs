use regex::Regex;
use serde::Deserialize;
use std::error::Error;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStringExt, OsStrExt};
use std::ptr;
use winapi::shared::winerror::S_OK;
use winapi::um::combaseapi::CoInitializeEx;
use winapi::um::combaseapi::CoUninitialize;
use winapi::um::objbase::COINIT_MULTITHREADED;
use winapi::um::winevt::{EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtRender, EvtRenderEventXml};
use wmi::{COMLibrary, WMIConnection, Variant};
use chrono::{DateTime, Utc};
use std::collections::HashMap;


fn main() {
    query_exclusion_paths();
    if let Err(e) = query_reg_asr_rules() {
        eprintln!("Error querying ASR rules: {}", e);
        let _ = query_asr_rules();
    }
    println!("[+] Allowed Threats of the system:");
    let _ = query_allowed_threats();

    println!("[+] Defender Protection History");
    let _ = query_protection_history();

    println!("[+] Exploit Guard Protection History");
    let _ = query_exploit_guard_protection_history();
    
    println!("[+] Windows Firewall Exclusions");
    let _ = query_firewall_exclusions();

}

pub fn asr_rule_descriptions() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("56a863a9-875e-4185-98a7-b882c64b5ce5".to_string(), "Block Exploit of Vulnerable Signed Drivers".to_string());
    map.insert("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c".to_string(), "Prevent Adobe Reader from creating child processes".to_string());
    map.insert("d4f940ab-401b-4efc-aadc-ad5f3c50688a".to_string(), "Prevent all Office applications from creating child processes".to_string());
    map.insert("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2".to_string(), "Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem".to_string());
    map.insert("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550".to_string(), "Block executable content from email client and webmail".to_string());
    map.insert("01443614-cd74-433a-b99e-2ecdc07bfc25".to_string(), "Block executable files unless they meet a prevalence, age, or trusted list criterion".to_string());
    map.insert("5beb7efe-fd9a-4556-801d-275e5ffc04cc".to_string(), "Block execution of potentially hidden scripts".to_string());
    map.insert("d3e037e1-3eb8-44c8-a917-57927947596d".to_string(), "Block JavaScript or VBScript from launching downloaded executable content".to_string());
    map.insert("3b576869-a4ec-4529-8536-b80a7769e899".to_string(), "Block Office applications from creating executable content".to_string());
    map.insert("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84".to_string(), "Prevent Office applications from injecting code into other processes".to_string());
    map.insert("26190899-1602-49e8-8b27-eb1d0a1ce869".to_string(), "Block Office Communication Application from Creating Child Processes".to_string());
    map.insert("e6db77e5-3df2-4cf1-b95a-636979351e5b".to_string(), "Block persistence via WMI event subscription".to_string());
    map.insert("d1e49aac-8f56-4280-b9ba-993a6d77406c".to_string(), "Block Process Creations from PSExec and WMI Commands".to_string());
    map.insert("33ddedf1-c6e0-47cb-833e-de6133960387".to_string(), "Block computer restarting in safe mode (preview)".to_string());
    map.insert("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4".to_string(), "Block untrusted and unsigned processes running from USB".to_string());
    map.insert("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb".to_string(), "Block the use of copied or imitated system utilities (preview)".to_string());
    map.insert("a8f5898e-1dc8-49a9-9878-85004b8a61e6".to_string(), "Block the creation of web shells for servers".to_string());
    map.insert("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b".to_string(), "Block Win32 API Calls from Office Macros".to_string());
    map.insert("c1db55ab-c21a-4637-bb3f-a12568109d35".to_string(), "How to use advanced ransomware protection".to_string());
    map
}

fn query_exclusion_paths() {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let paths_pattern = Regex::new(r"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^\s]+)").unwrap();
    let query_w: Vec<u16> = OsString::from("*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();

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

                if let Some(caps) = paths_pattern.captures(&message_str) {
                    println!("[+] Exclusion Path: {}", &caps[1]);
                
                    if let Some(time_created_str) = message_str.split("<TimeCreated SystemTime='").nth(1).and_then(|s| s.split("'").nth(0)) {
                        if let Ok(time_created) = DateTime::parse_from_rfc3339(time_created_str) {
                            let time_created_utc: DateTime<Utc> = time_created.with_timezone(&Utc);
                            println!("[!] Time Created: {}", time_created_utc);
                        } else {
                            eprintln!("Failed to parse time created: {}", time_created_str);
                        }
                    } else {
                        eprintln!("Failed to find time created in the event message");
                    }
                    println!();
                }
                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }
}


fn query_reg_asr_rules() -> Result<(), Box<dyn Error>> {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let asr_rule_id_pattern = Regex::new(r"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\\([0-9A-Fa-f-]+)").unwrap();
    let query_w: Vec<u16> = OsString::from("*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    let asr_descriptions = asr_rule_descriptions();

    unsafe {
        let h_query = EvtQuery(ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return Err(std::io::Error::last_os_error().into());
        }

        let mut events: [EVT_HANDLE; 10] = [ptr::null_mut(); 10];
        let mut returned = 0;

        while EvtNext(h_query, events.len() as u32, events.as_mut_ptr(), 0, 0, &mut returned) != 0 {
            for &event in &events[..returned as usize] {
                if event.is_null() {
                        return Err(std::io::Error::last_os_error().into());

                }

                let mut buffer_size: u32 = 0;
                EvtRender(ptr::null_mut(), event, EvtRenderEventXml, 0, ptr::null_mut(), &mut buffer_size, ptr::null_mut());
                let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

                if EvtRender(ptr::null_mut(), event, EvtRenderEventXml, buffer_size, buffer.as_mut_ptr() as *mut _, &mut buffer_size, ptr::null_mut()) == 0 {
                    eprintln!("Failed to render event");
                    EvtClose(event);
                    return Err(std::io::Error::last_os_error().into());
                }

                let message_str = OsString::from_wide(&buffer).to_string_lossy().into_owned();
                if let Some(caps) = asr_rule_id_pattern.captures(&message_str) {
                    let asr_rule_id = &caps[1].to_lowercase();
                    if let Some(description) = asr_descriptions.get(asr_rule_id) {
                        println!("[+] ASR Rule Triggered: {} - ({})",asr_rule_id , description);
                    } else {
                        println!("[+] ASR Rule Triggered: {}", asr_rule_id);
                    }

                    if let Some(time_created_str) = message_str.split("<TimeCreated SystemTime='").nth(1).and_then(|s| s.split("'").nth(0)) {
                        if let Ok(time_created) = DateTime::parse_from_rfc3339(time_created_str) {
                            let time_created_utc: DateTime<Utc> = time_created.with_timezone(&Utc);
                            println!("[!] Time Created: {}", time_created_utc);
                        } else {
                            eprintln!("Failed to parse time created: {}", time_created_str);
                        }
                    } else {
                        eprintln!("Failed to find time created in the event message");
                    }
                    println!();
                }

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }
    Ok(())
}



fn query_allowed_threats() -> Result<(), Box<dyn Error>> {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let query_w: Vec<u16> = OsString::from("*[System[(EventID=1117 or EventID=5007)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let h_query = EvtQuery(std::ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return Err(std::io::Error::last_os_error().into());
        }

        let mut events: [EVT_HANDLE; 10] = [std::ptr::null_mut(); 10];
        let mut returned = 0;

        let mut threat_details: HashMap<String, (String, String)> = HashMap::new();

        while EvtNext(h_query, events.len() as u32, events.as_mut_ptr(), 0, 0, &mut returned) != 0 {
            for &event in &events[..returned as usize] {
                if event.is_null() {
                    continue;
                }

                let mut buffer_size: u32 = 0;
                EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, 0, std::ptr::null_mut(), &mut buffer_size, std::ptr::null_mut());
                let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

                if EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, buffer_size, buffer.as_mut_ptr() as *mut _, &mut buffer_size, std::ptr::null_mut()) == 0 {
                    eprintln!("Failed to render event");
                    EvtClose(event);
                    continue;
                }

                let message_str = OsString::from_wide(&buffer).to_string_lossy().into_owned();
                let mut time_created = String::new();

                if let Some(event_id_str) = message_str.split("<EventID>").nth(1).and_then(|s| s.split("</EventID>").next()) {
                    let event_id: u32 = event_id_str.parse().unwrap_or(0);

                    if event_id == 1117 {
                        if let Some(threat_id) = message_str.split("threatid=").nth(1).and_then(|s| s.split("&").next()) {
                            let tool_name = message_str.split("<Data Name='Threat Name'>").nth(1).and_then(|s| s.split("</Data>").next()).unwrap_or("").to_string();
                            let path = message_str.split("<Data Name='Path'>").nth(1).and_then(|s| s.split("</Data>").next()).unwrap_or("").to_string();
                            threat_details.insert(threat_id.to_string(), (tool_name, path));
                        }
                    } else if event_id == 5007 {
                        if let Some(new_value) = message_str.split("<Data Name='New Value'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            if new_value.contains("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Threats\\ThreatIDDefaultAction") && new_value.ends_with("= 0x6") {
                                if let Some(threat_id) = new_value.split("ThreatIDDefaultAction\\").nth(1).and_then(|s| s.split(" = ").next()) {
                                    if let Some((tool_name, path)) = threat_details.get(threat_id) {
                                        if let Some(value) = message_str.split("<TimeCreated SystemTime='").nth(1).and_then(|s| s.split("'").nth(0)) {
                                            if let Ok(parsed_time) = DateTime::parse_from_rfc3339(value) {
                                                let time_created_utc: DateTime<Utc> = parsed_time.with_timezone(&Utc);
                                                time_created = time_created_utc.to_string();
                                            } else {
                                                eprintln!("Failed to parse time created: {}", value);
                                            }
                                        } else {
                                            eprintln!("Failed to find time created in the event message");
                                        }

                                        println!("ThreatID: {}", threat_id);
                                        println!("Tool Name: {}", tool_name);
                                        println!("Path: {}", path);
                                        println!("Time Created: {}", time_created);
                                        println!();
                                    }
                                }
                            }
                        }
                    }
                }

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }
    Ok(())
}



fn query_protection_history() -> Result<(), Box<dyn Error>> {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let query_w: Vec<u16> = OsString::from("*[System[(EventID=1117)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let h_query = EvtQuery(std::ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return Err(std::io::Error::last_os_error().into());
        }

        let mut events: [EVT_HANDLE; 10] = [std::ptr::null_mut(); 10];
        let mut returned = 0;

        while EvtNext(h_query, events.len() as u32, events.as_mut_ptr(), 0, 0, &mut returned) != 0 {
            for &event in &events[..returned as usize] {
                if event.is_null() {
                    continue;
                }

                let mut buffer_size: u32 = 0;
                EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, 0, std::ptr::null_mut(), &mut buffer_size, std::ptr::null_mut());
                let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

                if EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, buffer_size, buffer.as_mut_ptr() as *mut _, &mut buffer_size, std::ptr::null_mut()) == 0 {
                    eprintln!("Failed to render event");
                    EvtClose(event);
                    continue;
                }

                let message_str = OsString::from_wide(&buffer).to_string_lossy().into_owned();
                let mut threat_name = String::new();
                let mut severity_name = String::new();
                let mut category_name = String::new();
                let mut path = String::new();
                let mut action_name = String::new();
                let mut time_created = String::new();

                if let Some(event_id_str) = message_str.split("<EventID>").nth(1).and_then(|s| s.split("</EventID>").next()) {
                    let event_id: u32 = event_id_str.parse().unwrap_or(0);

                    if event_id == 1117 {
                        if let Some(value) = message_str.split("<Data Name='Threat Name'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            threat_name = value.to_string();
                        }

                        if let Some(value) = message_str.split("<Data Name='Severity Name'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            severity_name = value.to_string();
                        }

                        if let Some(value) = message_str.split("<Data Name='Category Name'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            category_name = value.to_string();
                        }

                        if let Some(value) = message_str.split("<Data Name='Path'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            path = value.to_string();
                        }

                        if let Some(value) = message_str.split("<Data Name='Action Name'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                            action_name = value.to_string();
                        }
                    }

                    if let Some(value) = message_str.split("<TimeCreated SystemTime='").nth(1).and_then(|s| s.split("'").nth(0)) {
                        if let Ok(parsed_time) = DateTime::parse_from_rfc3339(value) {
                            let time_created_utc: DateTime<Utc> = parsed_time.with_timezone(&Utc);
                            time_created = time_created_utc.to_string();
                        } else {
                            eprintln!("Failed to parse time created: {}", value);
                        }
                    } else {
                        eprintln!("Failed to find time created in the event message");
                    }

                    println!("Threat Name: {}", threat_name);
                    println!("Severity: {}", severity_name);
                    println!("Category: {}", category_name);
                    println!("Path: {}", path);
                    println!("Action Taken: {}", action_name);
                    println!("Time Created: {}", time_created);
                    println!();
                }

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }
    Ok(())
}



fn query_exploit_guard_protection_history() -> Result<(), Box<dyn Error>> {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Defender/Operational")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let query_w: Vec<u16> = OsString::from("*[System[(EventID=1121)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();

    let asr_descriptions = asr_rule_descriptions();

    unsafe {
        let h_query = EvtQuery(std::ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return Err(std::io::Error::last_os_error().into());
        }

        let mut events: [EVT_HANDLE; 10] = [std::ptr::null_mut(); 10];
        let mut returned = 0;

        while EvtNext(h_query, events.len() as u32, events.as_mut_ptr(), 0, 0, &mut returned) != 0 {
            for &event in &events[..returned as usize] {
                if event.is_null() {
                    continue;
                }

                let mut buffer_size: u32 = 0;
                EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, 0, std::ptr::null_mut(), &mut buffer_size, std::ptr::null_mut());
                let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

                if EvtRender(std::ptr::null_mut(), event, EvtRenderEventXml, buffer_size, buffer.as_mut_ptr() as *mut _, &mut buffer_size, std::ptr::null_mut()) == 0 {
                    eprintln!("Failed to render event");
                    EvtClose(event);
                    continue;
                }

                let message_str = OsString::from_wide(&buffer).to_string_lossy().into_owned();
                let mut rule_id = String::new();
                let mut detection_time = String::new();
                let mut user = String::new();
                let mut path = String::new();
                let mut process_name = String::new();
                let mut target_commandline = String::new();
                let mut description = String::new();

                if let Some(value) = message_str.split("<Data Name='ID'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    rule_id = value.to_lowercase();
                    description = asr_descriptions.get(&rule_id).cloned().unwrap_or_else(|| "Unknown ASR Rule".to_string());
                }

                if let Some(value) = message_str.split("<Data Name='Detection Time'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    if let Ok(parsed_time) = DateTime::parse_from_rfc3339(value) {
                        let time_created_utc: DateTime<Utc> = parsed_time.with_timezone(&Utc);
                        detection_time = time_created_utc.to_string();
                    } else {
                        eprintln!("Failed to parse detection time: {}", value);
                    }
                }

                if let Some(value) = message_str.split("<Data Name='User'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    user = value.to_string();
                }

                if let Some(value) = message_str.split("<Data Name='Path'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    path = value.to_string();
                }

                if let Some(value) = message_str.split("<Data Name='Process Name'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    process_name = value.to_string();
                }

                if let Some(value) = message_str.split("<Data Name='Target Commandline'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    target_commandline = value.to_string();
                }

                println!("Rule ID: {}", rule_id);
                println!("Description: {}", description);
                println!("Detection Time: {}", detection_time);
                println!("User: {}", user);
                println!("Path: {}", path);
                println!("Process Name: {}", process_name);
                println!("Target Commandline: {}", target_commandline);
                println!();

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }

    Ok(())
}


fn query_firewall_exclusions() -> Result<(), Box<dyn Error>> {
    let log_name_w: Vec<u16> = OsString::from("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let query_w: Vec<u16> = OsString::from("*[System[(EventID=2099)]]")
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let h_query = EvtQuery(ptr::null_mut(), log_name_w.as_ptr(), query_w.as_ptr(), EvtQueryChannelPath);
        if h_query.is_null() {
            eprintln!("Failed to query event log");
            return Err(std::io::Error::last_os_error().into());
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
                let mut rule_id = String::new();
                let mut rule_name = String::new();
                let mut application_path = String::new();
                let mut direction = String::new();
                let mut action = String::new();
                let mut time_created = String::new();
                let mut local_port = String::new();

                if let Some(value) = message_str.split("<Data Name='RuleId'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    rule_id = value.trim().to_string();
                }

                if let Some(value) = message_str.split("<Data Name='RuleName'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    rule_name = value.trim().to_string();
                }

                if let Some(value) = message_str.split("<Data Name='ApplicationPath'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    application_path = value.trim().to_string();
                }

                if let Some(value) = message_str.split("<Data Name='Direction'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    direction = value.trim().to_string();
                    if direction == "1"{
                        direction = "inbound".to_string()
                    }
                }

                if let Some(value) = message_str.split("<Data Name='Action'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    action = value.trim().to_string();
                }

                if let Some(value) = message_str.split("<Data Name='LocalPorts'>").nth(1).and_then(|s| s.split("</Data>").next()) {
                    local_port = value.trim().to_string();
                }

                if let Some(value) = message_str.split("<TimeCreated SystemTime='").nth(1).and_then(|s| s.split("'").next()) {
                    time_created = value.trim().to_string();
                }

                if action == "3" { // Action "3" corresponds to "Allow"
                    println!("Rule ID: {}", rule_id);
                    println!("Rule Name: {}", rule_name);
                    println!("Application Path: {}", application_path);
                    println!("Direction: {}", direction);
                    println!("Action: Allow");
                    println!("Local Port: {}", local_port);
                    println!("Time Created: {}", time_created);
                    println!();
                }

                EvtClose(event);
            }
        }

        EvtClose(h_query);
    }

    Ok(())
}


#[derive(Deserialize, Debug)]
struct MsftMpPreference {
    attack_surface_reduction_rules_actions: Option<Variant>,
    attack_surface_reduction_rules_ids: Option<Variant>,
}

mod funcs {


    pub fn printtable(asr_data: Vec<(String, String, String)>) {
        println!("{:-^100}", "-----------------------------------------------------------------------------------------------------");
        println!("{:<10} | {:<40} | {:<50}", "Enabled?", "ASR ID", "Name");
        println!("{:-^100}", "-----------------------------------------------------------------------------------------------------");
        for (action, id, name) in asr_data {
            println!("{:<10} | {:<40} | {:<50}", action, id, name);
        }
    }
}


fn variant_to_vec_u8(var: &Variant) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Variant::Array(arr) = var {
        let mut vec = Vec::new();
        for item in arr {
            if let Variant::UI1(byte) = item {
                vec.push(*byte);
            } else {
                return Err(Box::from("Expected byte array in Variant"));
            }
        }
        Ok(vec)
    } else {
        Err(Box::from("Expected Variant to be an Array"))
    }
}


fn variant_to_vec_string(var: &Variant) -> Result<Vec<String>, Box<dyn Error>> {
    if let Variant::Array(arr) = var {
        let mut vec = Vec::new();
        for item in arr {
            if let Variant::String(s) = item {
                vec.push(s.clone());
            } else {
                return Err(Box::from("Expected string array in Variant"));
            }
        }
        Ok(vec)
    } else {
        Err(Box::from("Expected Variant to be an Array"))
    }
}

fn query_asr_rules() -> Result<(), Box<dyn Error>> {
    
    let hr = unsafe { CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED) };
    if hr != S_OK {
        return Err(Box::from(format!("Failed to initialize COM library: HRESULT 0x{:X}", hr)));
    }

    let com_con = COMLibrary::new()?;
    

    
    let wmi_con = WMIConnection::with_namespace_path("ROOT\\Microsoft\\Windows\\Defender", com_con)?;

    let results: Vec<MsftMpPreference> = wmi_con.raw_query("SELECT * FROM MsftMpPreference")?;
    let mut asr_data = Vec::new();

    for result in results {
        if let (Some(actions), Some(ids)) = (&result.attack_surface_reduction_rules_actions, &result.attack_surface_reduction_rules_ids) {
            let actions_vec = match variant_to_vec_u8(actions) {
                Ok(v) => v,
                Err(e) => {
                    println!("Failed to convert actions to Vec<u8>: {}", e);
                    continue;
                }
            };

            let ids_vec = match variant_to_vec_string(ids) {
                Ok(v) => v,
                Err(e) => {
                    println!("Failed to convert ids to Vec<String>: {}", e);
                    continue;
                }
            };

            let actions_str: Vec<String> = actions_vec.iter().map(|b| format!("{:02X}", b)).collect();
            for (action, id) in actions_str.iter().zip(ids_vec.iter()) {
                let id_upper = id.to_lowercase();
                let name = asr_rule_descriptions().get(&id_upper).unwrap_or(&"Unknown ASR Rule".to_string()).clone();
                asr_data.push((action.clone(), id_upper, name));
            }
        } else {
            println!("No ASR rules found in this result.");
        }
    }
    
    funcs::printtable(asr_data);
    
    
    unsafe { CoUninitialize() };

    Ok(())
}
