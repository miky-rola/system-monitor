use std::collections::HashMap;
use std::os::raw::c_void;

use core_foundation::base::TCFType;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex, CFArrayRef};
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

type IOHIDEventSystemClientRef = *mut c_void;
type IOHIDServiceClientRef = *mut c_void;
type IOHIDEventRef = *mut c_void;

const PRIMARY_USAGE_PAGE_APPLE_VENDOR: i32 = 0xff00;
const PRIMARY_USAGE_TEMPERATURE_SENSOR: i32 = 5;
const EVENT_TYPE_TEMPERATURE: i64 = 15;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOHIDEventSystemClientCreate(allocator: *const c_void) -> IOHIDEventSystemClientRef;
    fn IOHIDEventSystemClientSetMatching(
        client: IOHIDEventSystemClientRef,
        matching: CFDictionaryRef,
    ) -> i32;
    fn IOHIDEventSystemClientCopyServices(client: IOHIDEventSystemClientRef) -> CFArrayRef;
    fn IOHIDServiceClientCopyProperty(
        service: IOHIDServiceClientRef,
        key: CFStringRef,
    ) -> CFTypeRef;
    fn IOHIDServiceClientCopyEvent(
        service: IOHIDServiceClientRef,
        event_type: i64,
        options: i64,
        timeout: i64,
    ) -> IOHIDEventRef;
    fn IOHIDEventGetFloatValue(event: IOHIDEventRef, field: i32) -> f64;
}

const READ_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 50;

pub fn read_sensors() -> HashMap<String, f32> {
    for attempt in 0..READ_ATTEMPTS {
        let readings = read_sensors_once();
        if !readings.is_empty() {
            return readings;
        }
        if attempt + 1 < READ_ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
        }
    }
    HashMap::new()
}

fn read_sensors_once() -> HashMap<String, f32> {
    let mut readings = HashMap::new();

    let matching = CFDictionary::from_CFType_pairs(&[
        (
            CFString::new("PrimaryUsagePage").as_CFType(),
            CFNumber::from(PRIMARY_USAGE_PAGE_APPLE_VENDOR).as_CFType(),
        ),
        (
            CFString::new("PrimaryUsage").as_CFType(),
            CFNumber::from(PRIMARY_USAGE_TEMPERATURE_SENSOR).as_CFType(),
        ),
    ]);

    unsafe {
        let client = IOHIDEventSystemClientCreate(std::ptr::null());
        if client.is_null() {
            return readings;
        }

        IOHIDEventSystemClientSetMatching(client, matching.as_concrete_TypeRef());

        let services = IOHIDEventSystemClientCopyServices(client);
        if services.is_null() {
            CFRelease(client as CFTypeRef);
            return readings;
        }

        let count = CFArrayGetCount(services);
        for index in 0..count {
            let service = CFArrayGetValueAtIndex(services, index) as IOHIDServiceClientRef;
            if service.is_null() {
                continue;
            }

            if let (Some(name), Some(celsius)) =
                (service_name(service), service_temperature(service))
            {
                if celsius.is_finite() && celsius > 0.0 {
                    readings.insert(name, celsius);
                }
            }
        }

        CFRelease(services as CFTypeRef);
        CFRelease(client as CFTypeRef);
    }

    readings
}

unsafe fn service_name(service: IOHIDServiceClientRef) -> Option<String> {
    let key = CFString::new("Product");
    let value = IOHIDServiceClientCopyProperty(service, key.as_concrete_TypeRef());
    if value.is_null() {
        return None;
    }
    let name = CFString::wrap_under_create_rule(value as CFStringRef).to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

unsafe fn service_temperature(service: IOHIDServiceClientRef) -> Option<f32> {
    let event = IOHIDServiceClientCopyEvent(service, EVENT_TYPE_TEMPERATURE, 0, 0);
    if event.is_null() {
        return None;
    }
    let field = (EVENT_TYPE_TEMPERATURE as i32) << 16;
    let celsius = IOHIDEventGetFloatValue(event, field) as f32;
    CFRelease(event as CFTypeRef);
    Some(celsius)
}
