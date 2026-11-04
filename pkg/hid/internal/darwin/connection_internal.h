#ifndef FIDO_HID_CONNECTION_INTERNAL_H
#define FIDO_HID_CONNECTION_INTERNAL_H
#include "native.h"
#include <pthread.h>
#ifdef HID_DIAGNOSTICS
#include "diagnostics_native.h"
#include <signal.h>
#endif

struct hid_connection {
    IOHIDDeviceRef device;
    pthread_t reader, writer;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    CFRunLoopRef runloop;
    int ready, stop, writer_stop, writer_dead;
    int terminal, head, count;
    uint32_t io_error, close_error;
    uint8_t input_id, output_id;
    int input_size, output_size;
    uint8_t input_buffer[HID_MAX_REPORT + 1];
    hid_report queue[HID_QUEUE_SIZE];
    uint8_t output_buffer[HID_MAX_REPORT + 1];
    int write_pending, write_done, output_length;
    hid_write_result write_result;
#ifdef HID_DIAGNOSTICS
    hid_diagnostic_probe *probe;
    uint64_t generation;
    int diagnostic_synthetic, diagnostic_recording;
    hid_diagnostic_config diagnostic_active;
    sigset_t diagnostic_before;
#endif
};
#endif
