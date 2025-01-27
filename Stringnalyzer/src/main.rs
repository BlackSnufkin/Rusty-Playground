use clap::Parser;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufReader, Read},
    path::PathBuf,
};

/// String Analyzer - A tool to analyze strings in binary files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the file to analyze
    #[arg(short, long)]
    file: PathBuf,

    /// Output format (json or jsonl)
    #[arg(short, long, default_value = "json")]
    format: String,

    /// Also extract wide (UTF-16) strings
    #[arg(short, long, default_value = "false")]
    wide: bool,
}

/// Common static lists
mod lists {
    pub const SUSPICIOUS_STRINGS: &[&str] = &[
        // Sandboxing/VM detection
        "VMwareService.exe", "VBoxService.exe", "DbgUiRemoteBreakin", "sbiedll.dll",
        "VBoxHook.dll", "VBoxMouse.sys", "VBoxGuest.sys", "vmware.exe",
        
        // Process tools & utilities
        "Process Hacker", "procexp.exe", "procmon.exe", "pestudio", "IDA Pro",
        "x64dbg.exe", "WinDbg.exe", "dnSpy.exe", "Ghidra.exe", 
        
        // Command & Control commands
        "cmd.exe /c", "powershell.exe -nop -w hidden -e", "certutil -urlcache -split -f",
        "mshta vbscript:CreateObject", "rundll32.exe javascript:",
        "odbcconf.exe /s /a {regsvr", "regsvr32 /s /n /u /i:",
        
        // Common malware paths
        "\\AppData\\Roaming", "\\Temp\\", "\\ProgramData\\", "\\Start Menu\\Programs\\Startup",
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "\\Tasks\\", "\\Prefetch\\",
        
        // Ransomware indicators
        "vssadmin delete shadows", "bcdedit /set {default}", "wbadmin delete catalog -quiet",
        "cipher /w:", "wevtutil cl", "del /f /q", ".readme.txt", ".paid", ".crypt",
        
        // Offensive tools & keywords
        "shellcode", "payload", "staged", "stageless", "reflective", "inject", "beacon",
        "loader", "dropper", "stager", "implant", "backdoor", "rootkit", "keylogger",
        "portscan", "lateral", "pivot", "exfil", "dump", "harvest", "hooking", "hook",
        "unhook", "patch", "bypass", "hollow", "spawned", "suspended", "injected", "injection",
        "elevated", "token", "steal", "impersonate", "migrate", "persistence",
        "encrypted", "obfuscated", "packed", "sandbox", "heartbeat", "callback",
        "handshake", "evasion", "stealth", "hidden", "covert", "masquerade", "spoof",
        "forge", "tunnel", "proxy", "relay", "listen", "bind", "reverse",
        "execute", "syscall", "indirect", "unmanaged", "native", "assembly",

        "mimikatz", "PSExec", "BloodHound", "Rubeus", "SharpHound", "Empire",
        "CobaltStrike", "meterpreter","inject", "mimikatz",
        
        // Common file extensions
        ".sys", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".msi",
        ".js", ".wsf", ".scr", ".pif", ".inf", ".reg", ".tmp", ".log"
    ];

    pub const SUSPICIOUS_FUNCTIONS: &[&str] = &[
        // Memory operations
        "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "NtWriteVirtualMemory",
        "ZwWriteVirtualMemory", "NtProtectVirtualMemory", "ZwProtectVirtualMemory",
        "NtCreateSection", "ZwCreateSection", "NtMapViewOfSection", "ZwMapViewOfSection",
        
        // Process/Thread operations
        "NtCreateThreadEx", "NtCreateProcess", "NtCreateUserProcess", "RtlCreateUserThread",
        "NtQueueApcThread", "NtQueueApcThread-S", "NtOpenProcess", "ZwOpenProcess",
        "NtSuspendProcess", "NtResumeProcess", "NtGetContextThread", "NtSetContextThread",
        
        // Injection techniques
        "VirtualAllocExNuma", "VirtualAlloc2", "VirtualAlloc2FromApp",
        "EnumSystemLocalesA", "EnumTimeFormatsA", "EnumDateFormatsA",
        "CreateFiber", "ConvertThreadToFiber", "FlsAlloc", "FlsSetValue",
        
        // Anti-debug/EDR
        "NtSetInformationThread", "NtSetInformationProcess", "NtQuerySystemInformation",
        "NtQueryInformationProcess", "NtSystemDebugControl", "NtYieldExecution",
        "NtSetDebugFilterState", "NtClose", "NtDuplicateObject",
        
        // DLL/Module operations
        "LdrLoadDll", "LdrGetDllHandle", "LdrGetProcedureAddress", "LdrUnloadDll",
        "LdrLockLoaderLock", "LdrUnlockLoaderLock", "LdrProcessRelocationBlock",
        
        // Network operations
        "NtDeviceIoControlFile", "WSAIoctl", "DeviceIoControl", "NtCreateNamedPipeFile",
        "PR_Write", "PR_Read", "SSL_Write", "SSL_Read", "WinHttpConnect"
    ];

    pub const NETWORK_INDICATORS: &[&str] = &[
        "HTTP/1.1", "GET /", "POST /", "PUT /", "DELETE /",
        "Content-Type:", "User-Agent:", "Host:", "Cookie:", "X-Forwarded-For:",
        "Mozilla/", "wget", "curl", "password=", "admin=", "auth=", "token=",
        ".onion", ".bit", ".top", ".xyz", ".win", ".cc", ".ru", ".cn",
        "api.", "cdn.", "update.", "secure.", "login.", "admin.", "vpn."
    ];

    pub const FILE_OPERATIONS: &[&str] = &[
        // System paths
        "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\",
        "C:\\Windows\\Microsoft.NET\\", "C:\\Windows\\assembly\\",
        "C:\\Windows\\diagnostics\\", "C:\\Windows\\System32\\config\\",
        
        // LOLBins
        "regsvr32.exe", "rundll32.exe", "mshta.exe", "wscript.exe",
        "cscript.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "pcalua.exe", "winrm.vbs", "dnscmd.exe", "diskshadow.exe",
        "installutil.exe", "msbuild.exe", "appcmd.exe", "mavinject.exe"
    ];
}
/// Regex patterns
static IP_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Strict 4-octet IPv4, to avoid OIDs like "1.3.14.3"
    Regex::new(
        r"(?x)
        \b
        (25[0-5]|2[0-4]\d|[01]?\d?\d)
        \.
        (25[0-5]|2[0-4]\d|[01]?\d?\d)
        \.
        (25[0-5]|2[0-4]\d|[01]?\d?\d)
        \.
        (25[0-5]|2[0-4]\d|[01]?\d?\d)
        \b
        "
    ).unwrap()
});

static URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(https?:\/\/(?:www\.)?[a-z0-9.-]+\.[a-z]{2,15}(?:\/[^\s\(\)\[\]\{\}<>]*)?)")
    .unwrap()
});
// First, modify the FILE_PATTERN to use a capturing group:
static FILE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?xi)
        # must either be start-of-string OR a character that is NOT ':' or '/'
        (?:^|[^:/])
        # capture just the filename
        \b([\w.-]+\.(?:exe|bat|cmd|vbs|txt|log|ini|reg|msi|sys|inf|drv|cpl|scr|hlp|ico|lnk))\b"
    ).unwrap()
});


static PATH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:[A-Z]:\\[^\\/:*?<>|\r\n]+(?:\\[^\\/:*?<>|\r\n]+)*\.[a-zA-Z0-9]{1,4}|/(?:usr|etc|var|bin)/[^/]+)").unwrap()
});

static DLL_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^.+\.dll$").unwrap());

static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
});
static DOMAIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.(?:com|net|org|edu|gov|mil|int|dev|biz|info|io|xyz)$").unwrap()
});
static REGISTRY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)HKEY_[^\\]+(?:\\[^\\]+)+").unwrap()
});

static INTERESTING_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap()
});

/// A ban-list for known compiler artifacts or C++ internals
static BAN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        (\.CRT\$ | \.rdata | \.pdata | \.xdata | \.didat\$) |
        (\? | @) |
        \b__thiscall\b | \b__cdecl\b | \b__clrcall\b | \b__stdcall\b | \b__fastcall\b | \b__vectorcall\b |
        D\$ | H9 | E3
        "
    ).unwrap()
});

static FUNCTION_CALL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // The parenthesis is now optional => `(?:\(\s*)?`
    Regex::new(r"(?xi)\b(?:set|get|rtl|nt)[a-z0-9_]+(?:\(\s*)?").unwrap()
});

static ERROR_MESSAGE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?xi)
        (?:
            error[\s:]+|
            failed\s+to[\s:]+|
            exception[\s:]+|
            unable\s+to[\s:]+|
            cannot[\s:]+|
            could\s+not[\s:]+|
            failure[\s:]+|
            fatal[\s:]+|
            critical[\s:]+|
            warning[\s:]+|
            denied[\s:]+|
            access\s+denied[\s:]+|
            permission\s+denied[\s:]+|
            unauthorized[\s:]+|
            timeout[\s:]+|
            connection\s+(?:failed|refused|reset)[\s:]+
        )
        [\w\s\-\.\,\/\\\(\)\[\]\{\}]+
    ").unwrap()
});


// Add this struct before AnalysisResults
#[derive(Hash, Eq, PartialEq)]
struct CaseInsensitiveString(String);

impl CaseInsensitiveString {
    fn new(s: &str) -> Self {
        CaseInsensitiveString(s.to_lowercase())
    }
}



#[derive(Default, Serialize)]
struct AnalysisResults {
    file_path: String,
    total_strings: usize,
    all_strings: Vec<String>,
    found_error_messages: Vec<String>,
    found_functions: Vec<String>,
    found_url: Vec<String>,
    found_dll: Vec<String>,
    found_ip: Vec<String>,
    found_path: Vec<String>,
    found_file: Vec<String>,
    found_commands: Vec<String>,
    found_suspicious_strings: Vec<String>,
    found_suspicious_functions: Vec<String>,
    found_network_indicators: Vec<String>,
    found_registry_keys: Vec<String>,
    found_interesting_strings: Vec<String>,
    found_file_operations: Vec<String>,
    found_emails: Vec<String>,
    found_domains: Vec<String>,
}

impl AnalysisResults {
    fn new(file_path: String) -> Self {
        Self {
            file_path,
            ..Default::default()
        }
    }

    fn deduplicate(&mut self) {
        fn make_unique(vec: &mut Vec<String>) {
            let set: HashSet<_> = vec.drain(..).collect();
            vec.extend(set.into_iter());
        }
        make_unique(&mut self.all_strings);
        make_unique(&mut self.found_functions);
        make_unique(&mut self.found_url);
        make_unique(&mut self.found_dll);
        make_unique(&mut self.found_ip);
        make_unique(&mut self.found_path);
        make_unique(&mut self.found_file);
        make_unique(&mut self.found_commands);
        make_unique(&mut self.found_suspicious_strings);
        make_unique(&mut self.found_suspicious_functions);
        make_unique(&mut self.found_network_indicators);
        make_unique(&mut self.found_registry_keys);
        make_unique(&mut self.found_interesting_strings);
        make_unique(&mut self.found_file_operations);
        make_unique(&mut self.found_emails);
        make_unique(&mut self.found_domains);
        make_unique(&mut self.found_error_messages);

    }

    fn output(&self, format: &str) -> io::Result<()> {
        match format {
            "json" => {
                println!("{}", serde_json::to_string_pretty(self)?);
            }
            "jsonl" => {
                let categories = [
                    ("functions", &self.found_functions),
                    ("suspicious_strings", &self.found_suspicious_strings),
                    ("suspicious_functions", &self.found_suspicious_functions),
                    ("network_indicators", &self.found_network_indicators),
                    ("registry_keys", &self.found_registry_keys),
                    ("interesting_strings", &self.found_interesting_strings),
                    ("error_messages", &self.found_error_messages),
                    ("url", &self.found_url),
                    ("ip", &self.found_ip),
                    ("domain", &self.found_domains),
                    ("email", &self.found_emails),
                    ("path", &self.found_path),
                    ("dll", &self.found_dll),
                    ("file", &self.found_file),
                    ("file_operations", &self.found_file_operations),
                    ("commands", &self.found_commands),
                ];
                for (category, items) in categories {
                    for value in items {
                        let match_entry = crate::StringMatch {
                            category: category.to_string(),
                            value: value.clone(),
                            file_path: self.file_path.clone(),
                        };
                        println!("{}", serde_json::to_string(&match_entry)?);
                    }
                }
            }
            _ => {
                eprintln!("Unsupported format: {}", format);
                std::process::exit(1);
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct StringMatch {
    category: String,
    value: String,
    file_path: String,
}

/// 1) Basic length / vowel / ratio checks
fn base_filter_junk(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let mut alpha_count = 0;
    let mut vowel_count = 0;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            alpha_count += 1;
            if matches!(c, 'a'|'e'|'i'|'o'|'u'|'A'|'E'|'I'|'O'|'U') {
                vowel_count += 1;
            }
        }
    }
    if alpha_count < 2 {
        return false;
    }
    if vowel_count == 0 {
        return false;
    }
    let ratio = alpha_count as f64 / s.len() as f64;
    if ratio < 0.30 {
        return false;
    }
    // skip if all the same character
    let first_char = s.chars().next().unwrap();
    if s.chars().all(|c| c == first_char) {
        return false;
    }
    true
}

/// 2) Additional ban pattern
fn ban_compiler_noise(s: &str) -> bool {
    BAN_PATTERN.is_match(s)
}

/// Merge both checks
fn final_filter(s: &str) -> bool {
    if !base_filter_junk(s) {
        return false;
    }
    if ban_compiler_noise(s) {
        return false;
    }
    true
}

/// Extract ASCII strings
fn get_ascii_strings<R: Read>(reader: &mut R) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut current_string = String::new();

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        for &byte in &buffer[..bytes_read] {
            if (32..=126).contains(&byte) {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= 6 {
                    result.push(current_string.clone());
                }
                current_string.clear();
            }
        }
    }
    if current_string.len() >= 6 {
        result.push(current_string);
    }
    Ok(result)
}

/// Extract UTF-16
fn get_wide_strings<R: Read>(reader: &mut R) -> io::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut temp = Vec::new();

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        temp.extend_from_slice(&buffer[..bytes_read]);
    }
    let mut wide_current = Vec::new();
    let mut i = 0;
    while i + 1 < temp.len() {
        let low = temp[i];
        let high = temp[i + 1];
        let wc = u16::from_le_bytes([low, high]);
        if (32..=126).contains(&wc) {
            wide_current.push(wc as u8 as char);
        } else {
            if wide_current.len() >= 6 {
                result.push(wide_current.iter().collect());
            }
            wide_current.clear();
        }
        i += 2;
    }
    if wide_current.len() >= 6 {
        result.push(wide_current.iter().collect());
    }
    Ok(result)
}

/// Analyze all extracted strings
fn analyze_strings(file_path: String, extracted_strings: &[String]) -> AnalysisResults {
    let mut results = AnalysisResults::new(file_path.clone());
    let mut kept = Vec::new();
    let mut processed_strings = HashSet::new(); // Track already categorized strings

    // Filter out junk / noise
    for s in extracted_strings {
        if final_filter(s) {
            kept.push(s.clone());
        }
    }
    results.total_strings = kept.len();
    results.all_strings = kept.clone();

    let malware_strings_set: HashSet<_> = lists::SUSPICIOUS_STRINGS.iter().copied().collect();
    let suspicious_functions_set: HashSet<_> = lists::SUSPICIOUS_FUNCTIONS.iter().copied().collect();
    let network_indicators_set: HashSet<_> = lists::NETWORK_INDICATORS.iter().copied().collect();
    let file_operations_set: HashSet<_> = lists::FILE_OPERATIONS.iter().copied().collect();

    for string in &results.all_strings {
        // Skip if we've already categorized this string
        if processed_strings.contains(string) {
            continue;
        }

        let lowercase_string = string.to_lowercase();

        // Order from most specific to most general patterns
        if malware_strings_set.iter().any(|s| lowercase_string.contains(&s.to_lowercase())) {
            results.found_suspicious_strings.push(string.clone());
            processed_strings.insert(string);
            continue;
        }
        if suspicious_functions_set.iter().any(|s| lowercase_string.contains(&s.to_lowercase())) {
            results.found_suspicious_functions.push(string.clone());
            processed_strings.insert(string);
            continue;
        }
        if network_indicators_set.iter().any(|s| lowercase_string.contains(&s.to_lowercase())) {
            results.found_network_indicators.push(string.clone());
            processed_strings.insert(string);
            continue;
        }
        if file_operations_set.iter().any(|s| lowercase_string.contains(&s.to_lowercase())) {
            results.found_file_operations.push(string.clone());
            processed_strings.insert(string);
            continue;
        }

        // Basic length limit for next checks
        if string.len() <= 200 {
            if let Some(captures) = URL_PATTERN.captures(string) {
                if let Some(url_match) = captures.get(1) {
                    results.found_url.push(url_match.as_str().to_string());
                }
            }
            if IP_PATTERN.is_match(string) {
                results.found_ip.push(string.clone());
                processed_strings.insert(string);
                continue;
            }
            if PATH_PATTERN.is_match(string) {
                results.found_path.push(string.clone());
            }
            if DLL_PATTERN.is_match(string) {
                results.found_dll.push(string.clone());
            }
            if let Some(captures) = FILE_PATTERN.captures(string) {
                if let Some(file_match) = captures.get(1) {
                    results.found_file.push(file_match.as_str().to_string());
                }
            }
            if FUNCTION_CALL_PATTERN.is_match(string) && 
               !ERROR_MESSAGE_PATTERN.is_match(string) {
                results.found_functions.push(string.clone());
            }
        }
        
        if ERROR_MESSAGE_PATTERN.is_match(string) {
            results.found_error_messages.push(string.clone());
        }

        if EMAIL_PATTERN.is_match(string) {
            results.found_emails.push(string.clone());
        }
        if DOMAIN_PATTERN.is_match(string) {
            results.found_domains.push(string.clone());
        }
        if REGISTRY_PATTERN.is_match(string) {
            results.found_registry_keys.push(string.clone());
        }
        if !ERROR_MESSAGE_PATTERN.is_match(string) && 
            INTERESTING_PATTERN.is_match(string) && 
            string.len() > 20 {
            results.found_interesting_strings.push(string.clone());
        }
    }

    results
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if !args.file.exists() {
        eprintln!("Error: File does not exist: {:?}", args.file);
        std::process::exit(1);
    }

    let file = File::open(&args.file)?;
    let mut reader = BufReader::new(file);
    let mut ascii_strings = get_ascii_strings(&mut reader)?;

    // Optionally parse wide (UTF-16) strings
    let wide_strings = if args.wide {
        let file2 = File::open(&args.file)?;
        let mut reader2 = BufReader::new(file2);
        get_wide_strings(&mut reader2)?
    } else {
        Vec::new()
    };

    // Combine ASCII + wide
    ascii_strings.extend(wide_strings);
    let all_strings = ascii_strings;

    // Analyze
    let mut results = analyze_strings(args.file.to_string_lossy().to_string(), &all_strings);

    // Deduplicate results
    results.deduplicate();

    // Output
    results.output(&args.format)?;

    Ok(())
}
