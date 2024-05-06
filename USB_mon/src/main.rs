use std::time::Duration;
use rusb::{Context, Device, UsbContext, Error};

#[derive(PartialEq)]
struct DeviceInfo {
    vendor_id: u16,
    product_id: u16,
    serial_number: String,
}

impl DeviceInfo {
    fn new<T: UsbContext>(device: &Device<T>) -> Result<Self, Error> {
        let device_desc = device.device_descriptor()?;
        let timeout = Duration::from_secs(1);
        let serial_number = match device.open() {
            Ok(handle) => match handle.read_languages(timeout) {
                Ok(languages) if !languages.is_empty() => {
                    handle
                        .read_serial_number_string(languages[0], &device_desc, timeout)
                        .unwrap_or_else(|_| String::new())
                }
                _ => String::new(),
            },
            Err(_) => String::new(),
        };
        Ok(DeviceInfo {
            vendor_id: device_desc.vendor_id(),
            product_id: device_desc.product_id(),
            serial_number,
        })
    }
}

fn main() -> Result<(), Error> {
    let context = Context::new()?;
    let mut known_devices: Vec<DeviceInfo> = Vec::new();
    let devices = context.devices()?;
    for device in devices.iter() {
        if let Ok(device_info) = DeviceInfo::new(&device) {
            known_devices.push(device_info);
        }
    }

    loop {
        
        let devices = context.devices()?;
        for device in devices.iter() {
            if let Ok(device_info) = DeviceInfo::new(&device) {
                if !known_devices.contains(&device_info) {
                    println!("New USB device connected:");
                    print_device_info(&device)?;
                    known_devices.push(device_info);
                }
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn print_device_info<T: UsbContext>(device: &Device<T>) -> Result<(), Error> {
    let device_desc = device.device_descriptor()?;
    let timeout = Duration::from_secs(1);
    let serial_number = match device.open() {
        Ok(handle) => match handle.read_languages(timeout) {
            Ok(languages) if !languages.is_empty() => {
                handle
                    .read_serial_number_string(languages[0], &device_desc, timeout)
                    .unwrap_or_else(|_| String::new())
            }
            _ => String::new(),
        },
        Err(_) => String::new(),
    };
    println!("  Vendor ID: {:04x}", device_desc.vendor_id());
    println!("  Product ID: {:04x}", device_desc.product_id());
    println!("  Serial Number: {}", serial_number);
    println!("  Bus Number: {:03}", device.bus_number());
    println!("  Device Address: {:03}", device.address());
    println!();
    Ok(())
}