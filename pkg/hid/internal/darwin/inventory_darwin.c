//go:build darwin && cgo

#include "native.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <mach/mach_error.h>
#include <stdlib.h>
#include <string.h>

static int number(IOHIDDeviceRef device, CFStringRef key, int *out) {
    CFTypeRef value = IOHIDDeviceGetProperty(device, key);
    return value && CFGetTypeID(value) == CFNumberGetTypeID() &&
           CFNumberGetValue(value, kCFNumberIntType, out);
}

static int string(IOHIDDeviceRef device, CFStringRef key, char *out, int size) {
    CFTypeRef value = IOHIDDeviceGetProperty(device, key);
    return value && CFGetTypeID(value) == CFStringGetTypeID() &&
           CFStringGetCString(value, out, size, kCFStringEncodingUTF8);
}

static int bus_type(IOHIDDeviceRef device) {
    char transport[64];
    if (!string(device, CFSTR(kIOHIDTransportKey), transport, sizeof(transport))) return 0;
    if (!strcmp(transport, "USB")) return 1;
    if (!strcmp(transport, "Bluetooth") || !strcmp(transport, "Bluetooth Low Energy")) return 2;
    if (!strcmp(transport, "I2C")) return 3;
    if (!strcmp(transport, "SPI")) return 4;
    return 5;
}

static int fill_entry(io_service_t service, int strings, hid_entry *entry) {
    memset(entry, 0, sizeof(*entry));
    if (IORegistryEntryGetRegistryEntryID(service, &entry->registry_id) != KERN_SUCCESS) return 0;
    entry->device = IOHIDDeviceCreate(kCFAllocatorDefault, service);
    if (!entry->device) return 0;
    io_string_t path;
    if (IORegistryEntryGetPath(service, kIOServicePlane, path) == KERN_SUCCESS)
        strlcpy(entry->path, path, sizeof(entry->path));
    int value;
    if (number(entry->device, CFSTR(kIOHIDVendorIDKey), &value) && value >= 0 && value <= UINT16_MAX) {
        entry->vendor = value; entry->known |= 1;
    }
    if (number(entry->device, CFSTR(kIOHIDProductIDKey), &value) && value >= 0 && value <= UINT16_MAX) {
        entry->product = value; entry->known |= 2;
    }
    // USB interface number is usually on an ancestor, not the HID service.
    CFTypeRef interface = IORegistryEntrySearchCFProperty(service, kIOServicePlane,
        CFSTR("bInterfaceNumber"), kCFAllocatorDefault,
        kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (interface) {
        if (CFGetTypeID(interface) == CFNumberGetTypeID() &&
            CFNumberGetValue(interface, kCFNumberIntType, &value) && value >= 0) {
            entry->interface_number = value; entry->known |= 4;
        }
        CFRelease(interface);
    }
    entry->bus = bus_type(entry->device);
    if (strings) {
        if (string(entry->device, CFSTR(kIOHIDSerialNumberKey), entry->serial, sizeof(entry->serial))) entry->known |= 8;
        if (string(entry->device, CFSTR(kIOHIDManufacturerKey), entry->manufacturer, sizeof(entry->manufacturer))) entry->known |= 16;
        if (string(entry->device, CFSTR(kIOHIDProductKey), entry->product_name, sizeof(entry->product_name))) entry->known |= 32;
    }
    CFTypeRef descriptor = IOHIDDeviceGetProperty(entry->device, CFSTR(kIOHIDReportDescriptorKey));
    if (descriptor && CFGetTypeID(descriptor) == CFDataGetTypeID()) {
        CFIndex length = CFDataGetLength(descriptor);
        if (length > 0 && length <= HID_MAX_DESCRIPTOR) {
            entry->descriptor = malloc((size_t)length);
            if (entry->descriptor) {
                memcpy(entry->descriptor, CFDataGetBytePtr(descriptor), (size_t)length);
                entry->descriptor_length = (int)length;
            } else entry->descriptor_length = -2;
        }
    }
    return 1;
}

static void clear_entry(hid_entry *entry) {
    if (entry->device) CFRelease(entry->device);
    free(entry->descriptor);
}

hid_inventory *hid_enumerate(int strings) {
    hid_inventory *inventory = calloc(1, sizeof(*inventory));
    if (!inventory) return NULL;
    inventory->complete = 1;
    io_iterator_t iterator = IO_OBJECT_NULL;
    inventory->error = IOServiceGetMatchingServices(kIOMainPortDefault,
        IOServiceMatching("IOHIDDevice"), &iterator);
    if (inventory->error) { inventory->complete = 0; return inventory; }
    io_service_t service;
    while ((service = IOIteratorNext(iterator))) {
        if (inventory->count >= HID_MAX_DEVICES) {
            inventory->complete = 0;
            inventory->limited = 1;
            IOObjectRelease(service);
            break;
        }
        hid_entry *entries = realloc(inventory->entries,
            (size_t)(inventory->count + 1) * sizeof(*entries));
        if (!entries) {
            inventory->complete = 0;
            inventory->limited = 1;
            IOObjectRelease(service);
            break;
        }
        inventory->entries = entries;
        if (fill_entry(service, strings, &entries[inventory->count])) inventory->count++;
        else inventory->complete = 0;
        IOObjectRelease(service);
    }
    if (!IOIteratorIsValid(iterator)) inventory->complete = 0;
    IOObjectRelease(iterator);
    return inventory;
}

void hid_inventory_free(hid_inventory *inventory) {
    if (!inventory) return;
    for (int i = 0; i < inventory->count; ++i) clear_entry(&inventory->entries[i]);
    free(inventory->entries);
    free(inventory);
}

hid_entry *hid_lookup(uint64_t registry_id, int strings, uint32_t *error) {
    *error = 0;
    CFMutableDictionaryRef matching = IORegistryEntryIDMatching(registry_id);
    if (!matching) { *error = kIOReturnNoMemory; return NULL; }
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (!service) { *error = kIOReturnNoDevice; return NULL; }
    hid_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) *error = kIOReturnNoMemory;
    else if (!IOObjectConformsTo(service, "IOHIDDevice") || !fill_entry(service, strings, entry)) {
        free(entry); entry = NULL; *error = kIOReturnError;
    }
    IOObjectRelease(service);
    return entry;
}

void hid_entry_free(hid_entry *entry) {
    if (!entry) return;
    clear_entry(entry);
    free(entry);
}

const char *hid_error_message(uint32_t code) { return mach_error_string((mach_error_t)code); }
