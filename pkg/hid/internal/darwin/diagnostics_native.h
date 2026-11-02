#ifndef FIDO_HID_DIAGNOSTICS_NATIVE_H
#define FIDO_HID_DIAGNOSTICS_NATIVE_H
#ifdef HID_DIAGNOSTICS
#include "native.h"
#include <signal.h>

typedef struct hid_diagnostic_probe hid_diagnostic_probe;
typedef struct {
    int initial_urgent_blocked, unrelated_blocked, inject_urgent, hold_native, strict_entry;
    int setup_error, restore_error;
    uint32_t native_error;
} hid_diagnostic_config;
typedef struct {
    uint64_t generation, writes, native_calls, kill_attempts, kill_generation, entry_generation;
    int synthetic, armed, phases, kill_error, initial_mask_error, mask_query_error;
    int before_urgent, before_unrelated, critical_urgent, pending_urgent;
    int after_urgent, after_unrelated, mask_restored;
    int setup_error, restore_error, submitted, completed;
    uint32_t native_error;
    int writer_exited, writer_joined, device_closed, entry_confirmed;
    int entry_urgent, entry_pending, entry_mask_error;
} hid_diagnostic_snapshot;

hid_diagnostic_probe *hid_diagnostic_probe_new(void);
void hid_diagnostic_probe_retain(hid_diagnostic_probe *p);
void hid_diagnostic_probe_release(hid_diagnostic_probe *p);
void hid_diagnostic_probe_close(hid_diagnostic_probe *p);
int hid_diagnostic_arm(hid_diagnostic_probe *p, hid_diagnostic_config config);
void hid_diagnostic_snapshot_read(hid_diagnostic_probe *p, hid_diagnostic_snapshot *out);
int hid_diagnostic_wait(hid_diagnostic_probe *p, int phase, int milliseconds);
void hid_diagnostic_release_barrier(hid_diagnostic_probe *p);
int hid_diagnostic_attach(hid_connection *c, hid_diagnostic_probe *p);
hid_connection *hid_diagnostic_connect(hid_diagnostic_probe *p, int *error);
int hid_diagnostic_input(hid_connection *c, const uint8_t *data, int length);
// LLDB must verify the actual IOHIDDeviceSetReport breakpoint before invoking.
// This helper uses native TLS and atomics only, never the connection mutex.
int hid_diagnostics_native_entry(uint64_t generation);
uint64_t hid_diagnostics_current_generation(void);

uint64_t hid_diagnostic_generation(void);
int hid_diagnostic_begin(hid_connection *c);
int hid_diagnostic_setup(hid_connection *c, const sigset_t *urgent, sigset_t *previous);
void hid_diagnostic_before_native(hid_connection *c);
void hid_diagnostic_after_native(hid_connection *c);
int hid_diagnostic_restore(hid_connection *c, const sigset_t *previous);
void hid_diagnostic_finish(hid_connection *c, hid_write_result result);
void hid_diagnostic_writer_exit(hid_connection *c);
void hid_diagnostic_writer_joined(hid_connection *c);
void hid_diagnostic_device_closed(hid_connection *c);
void hid_diagnostic_write_admit(hid_connection *c);
void hid_diagnostic_write_complete(hid_connection *c);
#endif
#endif
