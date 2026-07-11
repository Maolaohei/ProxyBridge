#ifndef NB_DNS_CACHE_H
#define NB_DNS_CACHE_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void dns_cache_init(void);
void dns_cache_free(void);
BOOL dns_cache_lookup(UINT32 ip, char *out_domain, size_t out_size);
BOOL dns_cache_lookup_v6(const UINT8 ip6[16], char *out_domain, size_t out_size);
/* Snoop inbound DNS response payload (DNS header at payload[0]). */
void snoop_dns_response(const UINT8 *payload, int payload_len);

#ifdef __cplusplus
}
#endif

#endif /* NB_DNS_CACHE_H */
