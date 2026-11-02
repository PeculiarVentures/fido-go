//go:build darwin && cgo && hid_diagnostics

#ifdef HID_DIAGNOSTICS
#include "connection_internal.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define DIAGNOSTIC_MAX_PROBES 64
#define PHASE_NATIVE 1
#define PHASE_EXITED 2
#define PHASE_JOINED 4
#define PHASE_CLOSED 8

struct hid_diagnostic_probe {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    atomic_uint references;
    int closing, busy, active, release;
    hid_diagnostic_config config;
    hid_diagnostic_snapshot snapshot;
    atomic_int strict_armed, entry_confirmed, entry_kill_error;
    atomic_int entry_urgent, entry_pending, entry_mask_error;
    atomic_uint_fast64_t entry_generation, entry_kills;
};

static atomic_uint probe_count;
static atomic_uint_fast64_t next_generation = 1;
static _Thread_local hid_diagnostic_probe *current_probe;
static _Thread_local uint64_t current_generation;

uint64_t hid_diagnostic_generation(void) {
    return atomic_fetch_add(&next_generation, 1);
}

hid_diagnostic_probe *hid_diagnostic_probe_new(void) {
    unsigned count = atomic_load(&probe_count);
    do {
        if (count >= DIAGNOSTIC_MAX_PROBES) return NULL;
    } while (!atomic_compare_exchange_weak(&probe_count, &count, count + 1));
    hid_diagnostic_probe *p = calloc(1, sizeof(*p));
    if (!p) goto failed;
    if (pthread_mutex_init(&p->lock, NULL)) { free(p); goto failed; }
    if (pthread_cond_init(&p->changed, NULL)) {
        pthread_mutex_destroy(&p->lock); free(p); goto failed;
    }
    atomic_init(&p->references, 1);
    atomic_init(&p->strict_armed, 0);
    atomic_init(&p->entry_confirmed, 0);
    atomic_init(&p->entry_kill_error, 0);
    atomic_init(&p->entry_generation, 0);
    atomic_init(&p->entry_kills, 0);
    atomic_init(&p->entry_urgent, 0);
    atomic_init(&p->entry_pending, 0);
    atomic_init(&p->entry_mask_error, 0);
    return p;
failed:
    atomic_fetch_sub(&probe_count, 1);
    return NULL;
}

void hid_diagnostic_probe_retain(hid_diagnostic_probe *p) { atomic_fetch_add(&p->references, 1); }

void hid_diagnostic_probe_release(hid_diagnostic_probe *p) {
    if (atomic_fetch_sub(&p->references, 1) != 1) return;
    pthread_cond_destroy(&p->changed);
    pthread_mutex_destroy(&p->lock);
    free(p);
    atomic_fetch_sub(&probe_count, 1);
}

int hid_diagnostic_attach(hid_connection *c, hid_diagnostic_probe *p) {
    pthread_mutex_lock(&c->lock);
    int error = 0;
    if (c->probe || c->write_pending || c->stop || c->terminal) error = EBUSY;
    else {
        hid_diagnostic_probe_retain(p);
        c->probe = p;
        pthread_mutex_lock(&p->lock);
        p->snapshot.generation = c->generation;
        p->snapshot.synthetic = c->diagnostic_synthetic;
        pthread_mutex_unlock(&p->lock);
    }
    pthread_mutex_unlock(&c->lock);
    return error;
}

int hid_diagnostic_arm(hid_diagnostic_probe *p, hid_diagnostic_config config) {
    pthread_mutex_lock(&p->lock);
    int error = 0;
    if (p->closing || p->snapshot.writer_exited || p->snapshot.device_closed) error = ECANCELED;
    else if (p->busy || p->active || p->snapshot.armed) error = EBUSY;
    else {
        p->config = config;
        p->snapshot.armed = 1;
        p->snapshot.phases &= ~PHASE_NATIVE;
        p->snapshot.mask_restored = 0;
        p->snapshot.pending_urgent = 0;
        p->snapshot.critical_urgent = 0;
        p->snapshot.initial_mask_error = 0;
        p->snapshot.mask_query_error = 0;
        p->snapshot.setup_error = 0;
        p->snapshot.restore_error = 0;
        p->snapshot.native_error = 0;
        p->snapshot.submitted = 0;
        p->snapshot.completed = 0;
        atomic_store(&p->entry_confirmed, 0);
        atomic_store(&p->entry_generation, 0);
        atomic_store(&p->entry_kill_error, 0);
        atomic_store(&p->entry_urgent, 0);
        atomic_store(&p->entry_pending, 0);
        atomic_store(&p->entry_mask_error, 0);
        p->release = 0;
    }
    pthread_mutex_unlock(&p->lock);
    return error;
}

void hid_diagnostic_snapshot_read(hid_diagnostic_probe *p, hid_diagnostic_snapshot *out) {
    pthread_mutex_lock(&p->lock);
    *out = p->snapshot;
    out->entry_confirmed = atomic_load(&p->entry_confirmed);
    out->entry_generation = atomic_load(&p->entry_generation);
    out->entry_urgent = atomic_load(&p->entry_urgent);
    out->entry_pending = atomic_load(&p->entry_pending);
    out->entry_mask_error = atomic_load(&p->entry_mask_error);
    uint64_t entry_kills = atomic_load(&p->entry_kills);
    out->kill_attempts += entry_kills;
    if (out->entry_confirmed) {
        out->kill_error = atomic_load(&p->entry_kill_error);
        out->kill_generation = out->entry_generation;
    }
    pthread_mutex_unlock(&p->lock);
}

int hid_diagnostic_wait(hid_diagnostic_probe *p, int phase, int milliseconds) {
    pthread_mutex_lock(&p->lock);
    int error = 0;
    if ((p->snapshot.phases & phase) != phase && !p->closing) {
        struct timespec relative = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };
        error = pthread_cond_timedwait_relative_np(&p->changed, &p->lock, &relative);
    }
    if ((p->snapshot.phases & phase) == phase) error = 0;
    else if (p->closing) error = ECANCELED;
    else if (!error) error = ETIMEDOUT;
    pthread_mutex_unlock(&p->lock);
    return error;
}

void hid_diagnostic_release_barrier(hid_diagnostic_probe *p) {
    pthread_mutex_lock(&p->lock);
    p->release = 1;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
}

// A probe's caller reference can be released while its connection owns it.
// Closing never waits for SetReport, an injector, or a device mutex.
void hid_diagnostic_probe_close(hid_diagnostic_probe *p) {
    pthread_mutex_lock(&p->lock);
    p->closing = 1;
    p->snapshot.armed = 0;
    p->release = 1;
    atomic_store(&p->strict_armed, 0);
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
    hid_diagnostic_probe_release(p);
}

void hid_diagnostic_write_admit(hid_connection *c) {
    if (!c->probe) return;
    pthread_mutex_lock(&c->probe->lock);
    c->probe->busy = 1;
    pthread_mutex_unlock(&c->probe->lock);
}

void hid_diagnostic_write_complete(hid_connection *c) {
    if (!c->probe) return;
    pthread_mutex_lock(&c->probe->lock);
    c->probe->busy = 0;
    pthread_cond_broadcast(&c->probe->changed);
    pthread_mutex_unlock(&c->probe->lock);
}

static int query_mask(sigset_t *out) { return pthread_sigmask(SIG_SETMASK, NULL, out); }

static int masks_equal(const sigset_t *left, const sigset_t *right) {
    for (int signal = 1; signal < NSIG; ++signal)
        if (sigismember(left, signal) != sigismember(right, signal)) return 0;
    return 1;
}

int hid_diagnostic_begin(hid_connection *c) {
    c->diagnostic_recording = 0;
    memset(&c->diagnostic_active, 0, sizeof(c->diagnostic_active));
    if (!c->probe) return 0;
    hid_diagnostic_probe *p = c->probe;
    pthread_mutex_lock(&p->lock);
    if (!p->snapshot.armed || p->closing) { pthread_mutex_unlock(&p->lock); return 0; }
    c->diagnostic_active = p->config;
    c->diagnostic_recording = 1;
    p->active = 1;
    p->snapshot.armed = 0;
    p->snapshot.writes++;
    p->snapshot.phases &= ~PHASE_NATIVE;
    p->snapshot.mask_restored = 0;
    p->snapshot.pending_urgent = 0;
    p->snapshot.critical_urgent = 0;
    p->snapshot.entry_confirmed = 0;
    atomic_store(&p->entry_confirmed, 0);
    atomic_store(&p->entry_generation, 0);
    atomic_store(&p->entry_kill_error, 0);
    pthread_mutex_unlock(&p->lock);

    sigset_t urgent, unrelated;
    sigemptyset(&urgent); sigaddset(&urgent, SIGURG);
    sigemptyset(&unrelated); sigaddset(&unrelated, SIGUSR1);
    int error = pthread_sigmask(c->diagnostic_active.initial_urgent_blocked ? SIG_BLOCK : SIG_UNBLOCK, &urgent, NULL);
    if (!error) error = pthread_sigmask(c->diagnostic_active.unrelated_blocked ? SIG_BLOCK : SIG_UNBLOCK, &unrelated, NULL);
    if (!error) error = query_mask(&c->diagnostic_before);
    pthread_mutex_lock(&p->lock);
    p->snapshot.initial_mask_error = error;
    if (!error) {
        p->snapshot.before_urgent = sigismember(&c->diagnostic_before, SIGURG) == 1;
        p->snapshot.before_unrelated = sigismember(&c->diagnostic_before, SIGUSR1) == 1;
    }
    pthread_mutex_unlock(&p->lock);
    return error;
}

int hid_diagnostic_setup(hid_connection *c, const sigset_t *urgent, sigset_t *previous) {
    if (c->diagnostic_recording && c->diagnostic_active.setup_error)
        return c->diagnostic_active.setup_error;
    return pthread_sigmask(SIG_BLOCK, urgent, previous);
}

typedef struct {
    hid_diagnostic_probe *probe;
    pthread_t writer;
    uint64_t generation;
    int ready, done;
} injection;

static void *inject_main(void *context) {
    injection *i = context;
    hid_diagnostic_probe *p = i->probe;
    pthread_mutex_lock(&p->lock);
    while (!i->ready) pthread_cond_wait(&p->changed, &p->lock);
    // The writer waits on this same condition and cannot exit or reuse its
    // pthread identity until it has joined this injector below.
    if (p->closing) p->snapshot.kill_error = ECANCELED;
    else {
        p->snapshot.kill_attempts++;
        p->snapshot.kill_generation = i->generation;
        p->snapshot.kill_error = pthread_kill(i->writer, SIGURG);
    }
    i->done = 1;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
    return NULL;
}

void hid_diagnostic_before_native(hid_connection *c) {
    if (!c->diagnostic_recording) return;
    hid_diagnostic_probe *p = c->probe;
    if (c->diagnostic_active.inject_urgent) {
        injection i = { .probe = p, .writer = pthread_self(), .generation = c->generation };
        pthread_t injector;
        int error = pthread_create(&injector, NULL, inject_main, &i);
        pthread_mutex_lock(&p->lock);
        if (error) p->snapshot.kill_error = error;
        else {
            i.ready = 1;
            pthread_cond_broadcast(&p->changed);
            while (!i.done) pthread_cond_wait(&p->changed, &p->lock);
        }
        pthread_mutex_unlock(&p->lock);
        if (!error) pthread_join(injector, NULL);
    }
    sigset_t mask, pending;
    int error = query_mask(&mask);
    if (!error && sigpending(&pending)) error = errno;
    pthread_mutex_lock(&p->lock);
    p->snapshot.mask_query_error = error;
    if (!error) {
        p->snapshot.critical_urgent = sigismember(&mask, SIGURG) == 1;
        p->snapshot.pending_urgent = sigismember(&pending, SIGURG) == 1;
    }
    p->snapshot.native_calls++;
    p->snapshot.phases |= PHASE_NATIVE;
    pthread_cond_broadcast(&p->changed);
    while (c->diagnostic_active.hold_native && !p->release && !p->closing)
        pthread_cond_wait(&p->changed, &p->lock);
    pthread_mutex_unlock(&p->lock);
    current_probe = p;
    current_generation = c->generation;
    atomic_store(&p->strict_armed, c->diagnostic_active.strict_entry && !c->diagnostic_synthetic);
}

// Called only by LLDB on the live dedicated writer at a verified native entry.
// No mutex, allocation, Go call, or stored pthread_t is used here.
__attribute__((used, noinline, visibility("default")))
uint64_t hid_diagnostics_current_generation(void) {
    return current_probe && atomic_load(&current_probe->strict_armed) ? current_generation : 0;
}

__attribute__((used, noinline, visibility("default")))
int hid_diagnostics_native_entry(uint64_t generation) {
    hid_diagnostic_probe *p = current_probe;
    if (!p || !atomic_load(&p->strict_armed) ||
        (generation && generation != current_generation)) return EINVAL;
    if (atomic_exchange(&p->entry_confirmed, 1)) return EALREADY;
    atomic_store(&p->entry_generation, current_generation);
    atomic_fetch_add(&p->entry_kills, 1);
    sigset_t mask, pending;
    int mask_error = query_mask(&mask);
    if (!mask_error) atomic_store(&p->entry_urgent, sigismember(&mask, SIGURG) == 1);
    int error = pthread_kill(pthread_self(), SIGURG);
    if (sigpending(&pending)) { if (!mask_error) mask_error = errno; }
    else atomic_store(&p->entry_pending, sigismember(&pending, SIGURG) == 1);
    atomic_store(&p->entry_mask_error, mask_error);
    atomic_store(&p->entry_kill_error, error);
    return error;
}

void hid_diagnostic_after_native(hid_connection *c) {
    if (!c->diagnostic_recording) return;
    atomic_store(&c->probe->strict_armed, 0);
    current_probe = NULL;
    current_generation = 0;
}

int hid_diagnostic_restore(hid_connection *c, const sigset_t *previous) {
    if (c->diagnostic_recording && c->diagnostic_active.restore_error)
        return c->diagnostic_active.restore_error;
    return pthread_sigmask(SIG_SETMASK, previous, NULL);
}

void hid_diagnostic_finish(hid_connection *c, hid_write_result result) {
    if (!c->diagnostic_recording) return;
    sigset_t after;
    int error = query_mask(&after);
    hid_diagnostic_probe *p = c->probe;
    pthread_mutex_lock(&p->lock);
    p->snapshot.setup_error = result.setup_error;
    p->snapshot.restore_error = result.restore_error;
    p->snapshot.native_error = result.io;
    p->snapshot.submitted = result.submitted;
    p->snapshot.completed = result.completed;
    if (error) p->snapshot.mask_query_error = error;
    else {
        p->snapshot.after_urgent = sigismember(&after, SIGURG) == 1;
        p->snapshot.after_unrelated = sigismember(&after, SIGUSR1) == 1;
        p->snapshot.mask_restored = !p->snapshot.initial_mask_error && masks_equal(&after, &c->diagnostic_before);
    }
    p->active = 0;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
}

void hid_diagnostic_writer_exit(hid_connection *c) {
    if (!c->probe) return;
    pthread_mutex_lock(&c->probe->lock);
    c->probe->snapshot.writer_exited = 1;
    c->probe->snapshot.phases |= PHASE_EXITED;
    pthread_cond_broadcast(&c->probe->changed);
    pthread_mutex_unlock(&c->probe->lock);
}

void hid_diagnostic_writer_joined(hid_connection *c) {
    if (!c->probe) return;
    pthread_mutex_lock(&c->probe->lock);
    c->probe->snapshot.writer_joined = 1;
    c->probe->snapshot.phases |= PHASE_JOINED;
    pthread_cond_broadcast(&c->probe->changed);
    pthread_mutex_unlock(&c->probe->lock);
}

void hid_diagnostic_device_closed(hid_connection *c) {
    if (!c->probe) return;
    hid_diagnostic_probe *p = c->probe;
    pthread_mutex_lock(&p->lock);
    p->snapshot.device_closed = 1;
    p->snapshot.phases |= PHASE_CLOSED;
    pthread_cond_broadcast(&p->changed);
    pthread_mutex_unlock(&p->lock);
    hid_diagnostic_probe_release(p);
}
#endif
