#ifndef NB_TOKEN_H
#define NB_TOKEN_H

#include <stdint.h>

/*
 * Token management for NetBridge protocol.
 *
 * The Bridge (Go) creates a random 32-bit token and writes it to
 * Windows Named Shared Memory "Local\BrayNBToken".
 * ProxyBridgeCore (C) reads this token at startup and includes it
 * in every NetBridge Header for authentication.
 *
 * This prevents other local processes from spoofing connections
 * to the Core's NetBridge port.
 */

/* Initialize token from Named Shared Memory.
 * Retries up to 20 times (500ms each = 10s total).
 * Returns 0 on success, -1 on failure. */
int nb_token_init(void);

/* Get the cached token value.
 * Returns 0 if nb_token_init() was never called or failed. */
uint32_t nb_token_get(void);

#endif /* NB_TOKEN_H */
