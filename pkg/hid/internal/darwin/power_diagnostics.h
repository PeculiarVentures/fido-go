#ifndef FIDO_POWER_DIAGNOSTICS_H
#define FIDO_POWER_DIAGNOSTICS_H
#ifdef HID_DIAGNOSTICS
#include <stdint.h>

typedef struct hid_power_observer hid_power_observer;
typedef struct {
    uint64_t observer_generation, arm_generation, will_sleep_generation, powered_on_generation;
    uint64_t sleep_sequence, wake_sequence, sequence;
    uint64_t can_sleep_events, sleep_events, wake_events, canceled_events;
    uint64_t out_of_order_events, extra_cycle_events, stale_events, ack_count, ack_errors;
    uint32_t native_code, deregister_code, service_close_code;
    int ready, armed, matched, closed, thread_joined, released, synthetic;
} hid_power_snapshot;

hid_power_observer *hid_power_new(int *thread_error, uint32_t *native_error);
int hid_power_arm(hid_power_observer *observer, uint64_t *generation, uint32_t *native_error);
void hid_power_snapshot_read(hid_power_observer *observer, hid_power_snapshot *snapshot);
int hid_power_wait(hid_power_observer *observer, uint64_t generation, int sleep_only, int milliseconds);
int hid_power_close(hid_power_observer *observer, hid_power_snapshot *snapshot);
// Shared pure reducer; fixture snapshots are synthetic and cannot enter an observer.
void hid_power_reduce(hid_power_snapshot *snapshot, uint64_t generation, int event, uint32_t ack_code);
#endif
#endif
