#ifndef NB_PROCNAME_H
#define NB_PROCNAME_H

#include <stdint.h>

/*
 * PID to process name resolution with SRWLock-protected cache.
 *
 * Called at packet capture time to immediately convert PID to process name.
 * The name is written into the NetBridge TCP Header so the Bridge (Go)
 * doesn't need to resolve it (avoiding PID reuse race conditions).
 *
 * Cache: 512-entry hash table, 5s TTL, SRWLock for concurrent access.
 */

/* Initialize the process name cache. Must be called once at startup. */
void nb_procname_init(void);

/* Get process name for a given PID.
 * Returns pointer to static buffer (valid until next call for same PID).
 * Returns empty string "" if PID cannot be resolved.
 * Thread-safe via SRWLock. */
const char* nb_procname_get(uint32_t pid);

/* Clear all cached entries. */
void nb_procname_clear(void);

#endif /* NB_PROCNAME_H */
