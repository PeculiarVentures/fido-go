//go:build darwin && cgo

#include "native.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
};

static void fail_locked(hid_connection *c, int terminal, uint32_t error) {
    if (!c->terminal) { c->terminal = terminal; c->io_error = error; }
    pthread_cond_broadcast(&c->changed);
}

static void input_callback(void *context, IOReturn result, void *sender,
                           IOHIDReportType type, uint32_t report_id,
                           uint8_t *report, CFIndex length) {
    (void)sender;
    hid_connection *c = context;
    pthread_mutex_lock(&c->lock);
    if (c->stop || c->terminal) goto done;
    if (result) { fail_locked(c, -1, result); goto done; }
    if (type != kIOHIDReportTypeInput || report_id != c->input_id) goto done;
    // IOKit delivers the complete wire report, including a nonzero Report ID.
    // The descriptor, never received length, determines whether it is present.
    int prefix = c->input_id != 0;
    if (length != c->input_size + prefix || (prefix && report[0] != c->input_id)) {
        fail_locked(c, -3, 0); goto done;
    }
    if (c->count == HID_QUEUE_SIZE) { fail_locked(c, -2, 0); goto done; }
    hid_report *queued = &c->queue[(c->head + c->count) % HID_QUEUE_SIZE];
    memcpy(queued->data, report + prefix, (size_t)c->input_size);
    queued->length = c->input_size;
    c->count++;
    pthread_cond_broadcast(&c->changed);
done:
    pthread_mutex_unlock(&c->lock);
}

static void removal_callback(void *context, IOReturn result, void *sender) {
    (void)result; (void)sender;
    hid_connection *c = context;
    pthread_mutex_lock(&c->lock);
    fail_locked(c, -1, kIOReturnNoDevice);
    pthread_mutex_unlock(&c->lock);
}

static void *reader_main(void *context) {
    hid_connection *c = context;
    IOReturn opened = IOHIDDeviceOpen(c->device, kIOHIDOptionsTypeNone);
    // An unsuccessful open exits this pthread immediately. Never publish its
    // borrowed runloop: the waiting opener may resume only after thread exit.
    CFRunLoopRef loop = opened ? NULL : CFRunLoopGetCurrent();
    if (!opened) {
        IOHIDDeviceRegisterInputReportCallback(c->device, c->input_buffer,
            sizeof(c->input_buffer), input_callback, c);
        IOHIDDeviceRegisterRemovalCallback(c->device, removal_callback, c);
        IOHIDDeviceScheduleWithRunLoop(c->device, loop, kCFRunLoopDefaultMode);
    }
    pthread_mutex_lock(&c->lock);
    c->runloop = loop;
    c->ready = 1;
    if (opened) fail_locked(c, -1, opened);
    pthread_cond_broadcast(&c->changed);
    pthread_mutex_unlock(&c->lock);
    if (opened) return NULL;
    for (;;) {
        pthread_mutex_lock(&c->lock);
        int stop = c->stop;
        pthread_mutex_unlock(&c->lock);
        if (stop) break;
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
    }
    // Teardown runs on the callback's own runloop thread. Unregister and
    // unschedule before closing, and join this thread before freeing context.
    IOHIDDeviceRegisterInputReportCallback(c->device, c->input_buffer,
        sizeof(c->input_buffer), NULL, NULL);
    IOHIDDeviceRegisterRemovalCallback(c->device, NULL, NULL);
    IOHIDDeviceUnscheduleFromRunLoop(c->device, loop, kCFRunLoopDefaultMode);
    c->close_error = IOHIDDeviceClose(c->device, kIOHIDOptionsTypeNone);
    pthread_mutex_lock(&c->lock);
    c->runloop = NULL;
    pthread_mutex_unlock(&c->lock);
    return NULL;
}

// All signal handling and submission stay inside a single C call on our own
// pthread. This thread is never borrowed from, or returned to, Go's scheduler.
static hid_write_result protected_write(hid_connection *c) {
    hid_write_result result = {0};
    sigset_t urgent, previous;
    if (sigemptyset(&urgent) || sigaddset(&urgent, SIGURG)) {
        result.setup_error = errno;
        return result;
    }
    result.setup_error = pthread_sigmask(SIG_BLOCK, &urgent, &previous);
    if (result.setup_error) return result;
    result.submitted = 1;
    result.io = IOHIDDeviceSetReport(c->device, kIOHIDReportTypeOutput,
        c->output_id, c->output_buffer, c->output_length);
    result.completed = result.io == kIOReturnSuccess;
    result.restore_error = pthread_sigmask(SIG_SETMASK, &previous, NULL);
    return result;
}

static void *writer_main(void *context) {
    hid_connection *c = context;
    pthread_mutex_lock(&c->lock);
    for (;;) {
        while (!c->write_pending && !c->writer_stop)
            pthread_cond_wait(&c->changed, &c->lock);
        if (c->writer_stop) break;
        pthread_mutex_unlock(&c->lock);
        hid_write_result result = protected_write(c);
        pthread_mutex_lock(&c->lock);
        c->write_result = result;
        c->write_pending = 0;
        c->write_done = 1;
        if (result.restore_error) {
            c->writer_dead = 1;
            fail_locked(c, -4, 0);
        }
        pthread_cond_broadcast(&c->changed);
        // A damaged signal mask never reaches any Go code, nor another write.
        if (c->writer_dead) break;
    }
    pthread_mutex_unlock(&c->lock);
    return NULL;
}

hid_connection *hid_connect(hid_entry *entry, uint8_t input_id, int input_size,
                           uint8_t output_id, int output_size,
                           uint32_t *io_error, int *thread_error) {
    *io_error = 0; *thread_error = 0;
    if (input_size < 1 || input_size > HID_MAX_REPORT || output_size < 1 || output_size > HID_MAX_REPORT) {
        *io_error = kIOReturnBadArgument; return NULL;
    }
    hid_connection *c = calloc(1, sizeof(*c));
    if (!c) { *io_error = kIOReturnNoMemory; return NULL; }
    c->device = (IOHIDDeviceRef)CFRetain(entry->device);
    c->input_id = input_id; c->input_size = input_size;
    c->output_id = output_id; c->output_size = output_size;
    *thread_error = pthread_mutex_init(&c->lock, NULL);
    if (*thread_error) goto free_storage;
    *thread_error = pthread_cond_init(&c->changed, NULL);
    if (*thread_error) goto destroy_lock;
    *thread_error = pthread_create(&c->reader, NULL, reader_main, c);
    if (*thread_error) goto destroy_cond;
    pthread_mutex_lock(&c->lock);
    while (!c->ready) pthread_cond_wait(&c->changed, &c->lock);
    *io_error = c->io_error;
    if (*io_error) {
        // Removal can race the readiness notification. A successfully opened
        // reader still needs a stop request before its thread can be joined.
        c->stop = 1;
        if (c->runloop) {
            CFRunLoopStop(c->runloop);
            CFRunLoopWakeUp(c->runloop);
        }
    }
    pthread_mutex_unlock(&c->lock);
    if (*io_error) { pthread_join(c->reader, NULL); goto destroy_cond; }
    *thread_error = pthread_create(&c->writer, NULL, writer_main, c);
    if (*thread_error) {
        pthread_mutex_lock(&c->lock);
        c->stop = 1;
        if (c->runloop) {
            CFRunLoopStop(c->runloop);
            CFRunLoopWakeUp(c->runloop);
        }
        pthread_mutex_unlock(&c->lock);
        pthread_join(c->reader, NULL);
        goto destroy_cond;
    }
    return c;
destroy_cond:
    pthread_cond_destroy(&c->changed);
destroy_lock:
    pthread_mutex_destroy(&c->lock);
free_storage:
    CFRelease(c->device);
    free(c);
    return NULL;
}

static int64_t monotonic_ns(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

int hid_read(hid_connection *c, int64_t wait_ns, hid_report *report, uint32_t *io_error) {
    int status = 0;
    int64_t started = monotonic_ns();
    *io_error = 0;
    pthread_mutex_lock(&c->lock);
    while (!c->count && !c->terminal && !c->stop) {
        if (!wait_ns) status = pthread_cond_wait(&c->changed, &c->lock);
        else {
            int64_t remaining = wait_ns - (monotonic_ns() - started);
            if (remaining <= 0) { status = ETIMEDOUT; break; }
            struct timespec relative = { remaining / 1000000000, remaining % 1000000000 };
            status = pthread_cond_timedwait_relative_np(&c->changed, &c->lock, &relative);
        }
        if (status) break;
    }
    if (c->terminal) { status = c->terminal; *io_error = c->io_error; }
    else if (c->stop) status = -5;
    else if (c->count) {
        *report = c->queue[c->head];
        c->head = (c->head + 1) % HID_QUEUE_SIZE;
        c->count--;
        status = 0;
    }
    pthread_mutex_unlock(&c->lock);
    return status;
}

void hid_write(hid_connection *c, const uint8_t *data, int length, hid_write_result *result) {
    memset(result, 0, sizeof(*result));
    pthread_mutex_lock(&c->lock);
    if (c->stop || c->terminal || c->writer_dead) {
        result->io = c->io_error ? c->io_error : kIOReturnNotOpen;
        pthread_mutex_unlock(&c->lock);
        return;
    }
    int prefix = c->output_id != 0;
    if (length != c->output_size) { result->io = kIOReturnBadArgument; goto done; }
    if (prefix) c->output_buffer[0] = c->output_id;
    memcpy(c->output_buffer + prefix, data, (size_t)length);
    c->output_length = length + prefix;
    c->write_pending = 1;
    c->write_done = 0;
    pthread_cond_broadcast(&c->changed);
    while (!c->write_done) pthread_cond_wait(&c->changed, &c->lock);
    *result = c->write_result;
done:
    pthread_mutex_unlock(&c->lock);
}

uint32_t hid_disconnect(hid_connection *c) {
    pthread_mutex_lock(&c->lock);
    c->writer_stop = 1;
    c->stop = 1;
    pthread_cond_broadcast(&c->changed);
    if (c->runloop) {
        CFRunLoopStop(c->runloop);
        CFRunLoopWakeUp(c->runloop);
    }
    pthread_mutex_unlock(&c->lock);
    pthread_join(c->writer, NULL);
    pthread_join(c->reader, NULL);
    uint32_t result = c->close_error;
    CFRelease(c->device);
    pthread_cond_destroy(&c->changed);
    pthread_mutex_destroy(&c->lock);
    free(c);
    return result;
}
