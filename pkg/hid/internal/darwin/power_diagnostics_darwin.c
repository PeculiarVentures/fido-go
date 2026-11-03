//go:build darwin && cgo && hid_diagnostics

#ifdef HID_DIAGNOSTICS
#include "power_diagnostics.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define MAX_POWER_OBSERVERS 8
enum { POWER_CAN_SLEEP = 1, POWER_WILL_SLEEP, POWER_POWERED_ON, POWER_WILL_NOT_SLEEP };
typedef struct {
    struct hid_power_observer *observer;
    uint64_t generation;
    io_connect_t root;
    io_object_t notifier;
    IONotificationPortRef port;
    CFRunLoopSourceRef source;
} power_registration;

struct hid_power_observer {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_t thread;
    CFRunLoopRef loop;
    power_registration registration;
    hid_power_snapshot snapshot;
    int started, stop, arm_requested, arm_done;
    uint32_t arm_error;
};

static atomic_uint observer_count;
static atomic_uint_fast64_t observer_generation = 1;

static void first_error(uint32_t *stored, uint32_t error) { if (!*stored) *stored = error; }

void hid_power_reduce(hid_power_snapshot *s, uint64_t generation, int event, uint32_t ack_code) {
    if (!s->armed) return;
    if (generation != s->arm_generation) { s->stale_events++; s->matched = 0; return; }
    s->sequence++;
    if (event == POWER_CAN_SLEEP || event == POWER_WILL_SLEEP) {
        s->ack_count++;
        if (ack_code) { s->ack_errors++; first_error(&s->native_code, ack_code); }
    }
    switch (event) {
    case POWER_CAN_SLEEP:
        if (++s->can_sleep_events > 1 || s->sleep_events || s->wake_events) s->extra_cycle_events++;
        break;
    case POWER_WILL_SLEEP:
        if (++s->sleep_events == 1 && !s->wake_events && !s->canceled_events) {
            s->will_sleep_generation = generation;
            s->sleep_sequence = s->sequence;
        } else { s->extra_cycle_events++; s->out_of_order_events++; }
        break;
    case POWER_POWERED_ON:
        if (++s->wake_events == 1 && s->sleep_events == 1 && s->sleep_sequence && !s->canceled_events) {
            s->powered_on_generation = generation;
            s->wake_sequence = s->sequence;
        } else { s->out_of_order_events++; if (s->wake_events > 1) s->extra_cycle_events++; }
        break;
    case POWER_WILL_NOT_SLEEP:
        s->canceled_events++;
        break;
    default:
        s->out_of_order_events++;
        break;
    }
    s->matched = s->sleep_events == 1 && s->wake_events == 1 &&
        s->will_sleep_generation == s->arm_generation && s->powered_on_generation == s->arm_generation &&
        s->sleep_sequence && s->wake_sequence > s->sleep_sequence && !s->canceled_events &&
        !s->out_of_order_events && !s->extra_cycle_events && !s->stale_events && !s->ack_errors;
}

static void power_callback(void *context, io_service_t service, natural_t message, void *argument) {
    (void)service;
    power_registration *r = context;
    // Acknowledge immediately, before acquiring any observer lock. Never veto
    // or initiate sleep, and never acknowledge WillNotSleep or wake messages.
    uint32_t ack = 0;
    int event = 0;
    if (message == kIOMessageCanSystemSleep || message == kIOMessageSystemWillSleep)
        ack = IOAllowPowerChange(r->root, (intptr_t)argument);
    switch (message) {
    case kIOMessageCanSystemSleep: event = POWER_CAN_SLEEP; break;
    case kIOMessageSystemWillSleep: event = POWER_WILL_SLEEP; break;
    case kIOMessageSystemHasPoweredOn: event = POWER_POWERED_ON; break;
    case kIOMessageSystemWillNotSleep: event = POWER_WILL_NOT_SLEEP; break;
    default: return;
    }
    hid_power_observer *p = r->observer;
    pthread_mutex_lock(&p->lock);
    // Even before Arm, a failed mandatory acknowledgement is a native error.
    // Do not discard it when a later arm rotates registration.
    if (!p->snapshot.armed && ack) {
        p->snapshot.ack_errors++;
        first_error(&p->snapshot.native_code, ack);
    }
    hid_power_reduce(&p->snapshot, r->generation, event, ack);
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
}

// Registration and teardown are confined to the callback's owner thread.
static uint32_t unregister_power(hid_power_observer *p) {
    power_registration *r = &p->registration;
    if (r->source) CFRunLoopRemoveSource(CFRunLoopGetCurrent(), r->source, kCFRunLoopDefaultMode);
    uint32_t deregister = r->notifier ? IODeregisterForSystemPower(&r->notifier) : 0;
    if (r->port) IONotificationPortDestroy(r->port);
    uint32_t closed = r->root ? IOServiceClose(r->root) : 0;
    memset(r, 0, sizeof(*r));
    pthread_mutex_lock(&p->lock);
    first_error(&p->snapshot.deregister_code, deregister);
    first_error(&p->snapshot.service_close_code, closed);
    first_error(&p->snapshot.native_code, deregister ? deregister : closed);
    pthread_mutex_unlock(&p->lock);
    return deregister ? deregister : closed;
}

static uint32_t register_power(hid_power_observer *p, uint64_t generation) {
    power_registration *r = &p->registration;
    r->observer = p;
    r->generation = generation;
    r->root = IORegisterForSystemPower(r, &r->port, power_callback, &r->notifier);
    if (!r->root) return kIOReturnError;
    r->source = IONotificationPortGetRunLoopSource(r->port);
    if (!r->source) return kIOReturnNoMemory;
    CFRunLoopAddSource(CFRunLoopGetCurrent(), r->source, kCFRunLoopDefaultMode);
    return 0;
}

static void *power_main(void *context) {
    hid_power_observer *p = context;
    uint32_t error = register_power(p, 0);
    pthread_mutex_lock(&p->lock);
    p->loop = CFRunLoopGetCurrent();
    p->snapshot.ready = !error;
    first_error(&p->snapshot.native_code, error);
    p->started = 1;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
    while (!error) {
        pthread_mutex_lock(&p->lock);
        int stop = p->stop, arm = p->arm_requested;
        pthread_mutex_unlock(&p->lock);
        if (stop) break;
        if (arm) {
            // Rotate the native registration to discard queued pre-arm events;
            // callbacks from the old source cannot run after owner-thread removal.
            pthread_mutex_lock(&p->lock);
            error = p->snapshot.native_code;
            pthread_mutex_unlock(&p->lock);
            if (!error) error = unregister_power(p);
            pthread_mutex_lock(&p->lock);
            uint64_t generation = p->snapshot.arm_generation + 1;
            uint64_t observer = p->snapshot.observer_generation;
            pthread_mutex_unlock(&p->lock);
            if (!generation && !error) error = kIOReturnNoResources;
            if (!error) error = register_power(p, generation);
            pthread_mutex_lock(&p->lock);
            if (!error) {
                memset(&p->snapshot, 0, sizeof(p->snapshot));
                p->snapshot.observer_generation = observer;
                p->snapshot.arm_generation = generation;
                p->snapshot.ready = p->snapshot.armed = 1;
            } else first_error(&p->snapshot.native_code, error);
            p->arm_error = error;
            p->arm_requested = 0;
            p->arm_done = 1;
            pthread_cond_broadcast(&p->changed);
            pthread_mutex_unlock(&p->lock);
        }
        if (!error) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.02, true);
    }
    unregister_power(p);
    pthread_mutex_lock(&p->lock);
    p->loop = NULL;
    p->snapshot.armed = 0;
    p->snapshot.closed = 1;
    p->snapshot.released = !p->snapshot.deregister_code && !p->snapshot.service_close_code;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
    return NULL;
}

hid_power_observer *hid_power_new(int *thread_error, uint32_t *native_error) {
    *thread_error = 0; *native_error = 0;
    unsigned count = atomic_load(&observer_count);
    do { if (count >= MAX_POWER_OBSERVERS) { *thread_error = EAGAIN; return NULL; } }
    while (!atomic_compare_exchange_weak(&observer_count, &count, count + 1));
    hid_power_observer *p = calloc(1, sizeof(*p));
    if (!p) { *thread_error = ENOMEM; goto failed; }
    p->snapshot.observer_generation = atomic_fetch_add(&observer_generation, 1);
    *thread_error = pthread_mutex_init(&p->lock, NULL);
    if (*thread_error) { free(p); goto failed; }
    *thread_error = pthread_cond_init(&p->changed, NULL);
    if (*thread_error) { pthread_mutex_destroy(&p->lock); free(p); goto failed; }
    *thread_error = pthread_create(&p->thread, NULL, power_main, p);
    if (*thread_error) {
        pthread_cond_destroy(&p->changed); pthread_mutex_destroy(&p->lock); free(p); goto failed;
    }
    pthread_mutex_lock(&p->lock);
    while (!p->started) pthread_cond_wait(&p->changed, &p->lock);
    *native_error = p->snapshot.native_code;
    pthread_mutex_unlock(&p->lock);
    return p;
failed:
    atomic_fetch_sub(&observer_count, 1);
    return NULL;
}

int hid_power_arm(hid_power_observer *p, uint64_t *generation, uint32_t *native_error) {
    pthread_mutex_lock(&p->lock);
    if (!p->snapshot.ready || p->snapshot.closed || p->stop || p->snapshot.native_code) {
        *native_error = p->snapshot.native_code;
        pthread_mutex_unlock(&p->lock); return ECANCELED;
    }
    p->arm_requested = 1; p->arm_done = 0;
    CFRunLoopStop(p->loop); CFRunLoopWakeUp(p->loop);
    while (!p->arm_done && !p->snapshot.closed) pthread_cond_wait(&p->changed, &p->lock);
    *generation = p->snapshot.arm_generation;
    *native_error = p->arm_error;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

void hid_power_snapshot_read(hid_power_observer *p, hid_power_snapshot *snapshot) {
    pthread_mutex_lock(&p->lock); *snapshot = p->snapshot; pthread_mutex_unlock(&p->lock);
}

int hid_power_wait(hid_power_observer *p, uint64_t generation, int sleep_only, int milliseconds) {
    pthread_mutex_lock(&p->lock);
    int error = 0;
    if (!generation || p->snapshot.arm_generation != generation) error = EINVAL;
    else if (!p->snapshot.closed && !p->snapshot.native_code &&
        !(sleep_only ? p->snapshot.sleep_events : p->snapshot.matched)) {
        struct timespec wait = {milliseconds / 1000, (milliseconds % 1000) * 1000000L};
        error = pthread_cond_timedwait_relative_np(&p->changed, &p->lock, &wait);
    }
    if (!error || error == ETIMEDOUT) {
        hid_power_snapshot *s = &p->snapshot;
        if (s->closed) error = ECANCELED;
        else if (s->native_code || s->out_of_order_events || s->extra_cycle_events || s->stale_events || s->canceled_events) error = EPROTO;
        else if (sleep_only ? s->sleep_events == 1 : s->matched) error = 0;
        else error = ETIMEDOUT;
    }
    pthread_mutex_unlock(&p->lock);
    return error;
}

int hid_power_close(hid_power_observer *p, hid_power_snapshot *snapshot) {
    pthread_mutex_lock(&p->lock);
    p->stop = 1;
    if (p->loop) { CFRunLoopStop(p->loop); CFRunLoopWakeUp(p->loop); }
    pthread_mutex_unlock(&p->lock);
    int error = pthread_join(p->thread, NULL);
    if (error) return error;
    p->snapshot.thread_joined = 1;
    *snapshot = p->snapshot;
    pthread_cond_destroy(&p->changed);
    pthread_mutex_destroy(&p->lock);
    if (snapshot->released) atomic_fetch_sub(&observer_count, 1);
    free(p);
    return 0;
}
#endif
