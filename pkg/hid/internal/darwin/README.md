The macOS backend uses IOKit and CoreFoundation directly. Registry entry IDs and
descriptor Application collection indexes form exact endpoint addresses. Inventory
does not open sessions, and optional strings are read only when requested.

Each open connection owns a native callback runloop, a 64-report native ring, and
a dedicated writer pthread. Callback contexts and retained buffers contain no Go
pointers. Close joins both pthreads after unregistering and unscheduling callbacks;
the public supervisor keeps the connection alive while native work is pending.

Writes currently use synchronous `IOHIDDeviceSetReport`, protected by a single C
wrapper that saves the pthread signal mask, blocks SIGURG, submits, and restores
the original mask. A failed setup prevents submission. A failed restoration
preserves the I/O result and pthread error, retires the writer, and terminates that
pthread. The thread is never borrowed from Go's scheduler. A blocked submission
remains owned by the public supervisor until completion; a caller timeout cannot
free native memory. Async SetReport qualification remains follow-up work.

Report IDs are separate in the Go contract. Numbered IOKit wire buffers include
their descriptor-defined leading ID; unnumbered reports have no artificial zero
byte. Only unambiguous USB FIDO Input/Output layouts are currently qualified for
opening. Feature reports and non-USB I/O are unsupported. Hardware qualification,
including numbered reports, SIGURG injection, removal, sleep/wake, and allocation
tracking, is required before production release.
