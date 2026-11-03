#ifndef FIDO_SHARED_POWER_DIAGNOSTICS_H
#define FIDO_SHARED_POWER_DIAGNOSTICS_H
#ifdef POWER_DIAGNOSTICS
#include <stdint.h>

typedef struct diagnostic_power_observer diagnostic_power_observer;
typedef struct {
    uint64_t observer_generation, arm_generation, will_sleep_generation, powered_on_generation;
    uint64_t sleep_sequence, wake_sequence, sequence;
    uint64_t can_sleep_events, sleep_events, wake_events, canceled_events;
    uint64_t out_of_order_events, extra_cycle_events, stale_events, ack_count, ack_errors;
    uint32_t native_code, deregister_code, service_close_code;
    int ready, armed, matched, closed, thread_joined, released, synthetic;
} diagnostic_power_snapshot;

diagnostic_power_observer *diagnostic_power_new(int *thread_error, uint32_t *native_error);
int diagnostic_power_arm(diagnostic_power_observer *observer, uint64_t *generation, uint32_t *native_error);
void diagnostic_power_snapshot_read(diagnostic_power_observer *observer, diagnostic_power_snapshot *snapshot);
int diagnostic_power_wait(diagnostic_power_observer *observer, uint64_t generation, int sleep_only, int milliseconds);
int diagnostic_power_close(diagnostic_power_observer *observer, diagnostic_power_snapshot *snapshot);
// Shared pure reducer; fixture snapshots are synthetic and cannot enter an observer.
void diagnostic_power_reduce(diagnostic_power_snapshot *snapshot, uint64_t generation, int event, uint32_t ack_code);
#endif
#endif
