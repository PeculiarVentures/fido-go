// Native storage is owned by these bindings; no callback enters Go.
#ifndef FIDO_NATIVE_HID_H
#define FIDO_NATIVE_HID_H
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDLib.h>
#include <stdint.h>

#define HID_MAX_REPORT 4096
#define HID_QUEUE_SIZE 64
#define HID_MAX_DESCRIPTOR 65536
#define HID_MAX_DEVICES 128

typedef struct {
    IOHIDDeviceRef device;
    uint64_t registry_id;
    uint32_t known;
    uint16_t vendor, product;
    int interface_number, bus;
    char path[1024], serial[1024], manufacturer[1024], product_name[1024];
    uint8_t *descriptor;
    int descriptor_length;
} hid_entry;

typedef struct {
    hid_entry *entries;
    int count, complete, limited;
    uint32_t error;
} hid_inventory;

typedef struct hid_connection hid_connection;
typedef struct { uint8_t data[HID_MAX_REPORT]; int length; } hid_report;
typedef struct {
    uint32_t io;
    int setup_error, restore_error, submitted, completed;
} hid_write_result;

hid_inventory *hid_enumerate(int strings);
void hid_inventory_free(hid_inventory *inventory);
hid_entry *hid_lookup(uint64_t registry_id, int strings, uint32_t *error);
void hid_entry_free(hid_entry *entry);
hid_connection *hid_connect(hid_entry *entry, uint8_t input_id, int input_size,
                           uint8_t output_id, int output_size,
                           uint32_t *io_error, int *thread_error);
// Returns 0, ETIMEDOUT, or a negative binding status (see darwin.go).
int hid_read(hid_connection *connection, int64_t wait_ns, hid_report *report,
             uint32_t *io_error);
void hid_write(hid_connection *connection, const uint8_t *data, int length,
               hid_write_result *result);
uint32_t hid_disconnect(hid_connection *connection);
const char *hid_error_message(uint32_t code);
#endif
