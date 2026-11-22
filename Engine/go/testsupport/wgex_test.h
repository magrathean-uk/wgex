// SPDX-License-Identifier: MIT

// WGEX engine test-support ABI (module CWGEXEngineTest). Linked only by test
// targets through WGEXEngineTest.xcframework (macOS slice); never shipped in
// products. Requires wgex.h.
#pragma once
#include <stdint.h>
#include "wgex.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1. Proves the wgextest build tag reached the archive. */
int32_t      wgex_test_ping(void);

/* Two engines over loopback UDP with gVisor netstack tuns; each side serves HTTP on port 80 of
   its in-tunnel address ("/" -> "wgex-test a|b", "/ip" -> caller's in-tunnel address,
   "/bytes?n=N" -> N bytes). json (may be NULL): {"addresses":["10.99.0.1","10.99.0.2"],
   "mtu":1420,"keepalive":0,"configure":true,"up":true}. a and b (may be NULL) supply callbacks,
   bind indexes and transport; their tun fields are ignored. With configure (default), throwaway
   keys, peers, loopback listen ports and endpoints are applied and, with up, both engines are
   up. Returns a pair id > 0 or WGEX_EINVAL. The engine handles work with every wgex_* call. */
int64_t      wgex_test_pair_create(const char *json, const wgex_create_params *a, const wgex_create_params *b);
/* Engine handle of side 0 (a) or 1 (b). */
wgex_handle  wgex_test_pair_engine(int64_t pair, int32_t side);
/* {"pair","handles":[a,b],"addresses":[..],"public_keys":[b64,b64],"listen_ports":[..],
   "uapi":[docA,docB]} (full documents with the throwaway keys); free with wgex_free. */
char        *wgex_test_pair_info(int64_t pair);
/* GET http://<other side>:80<path> through side from_side's tunnel; blocks up to timeout_ms
   (default 5000). {"status":n,"body":"..","error":".."}; free with wgex_free. */
char        *wgex_test_pair_http_get(int64_t pair, int32_t from_side, const char *path, int32_t timeout_ms);
/* Test-only tun Read failure injection; never available in production. */
int32_t      wgex_test_pair_fail_tun(int64_t pair, int32_t side);
/* Destroys both engines (if not already destroyed) and the HTTP servers. */
int32_t      wgex_test_pair_destroy(int64_t pair);

/* Echoes every datagram read from a duplicate of fd (a SOCK_DGRAM socketpair end) back to it,
   through the tun_kind 1 device. Returns an echo handle > 0 or WGEX_EINVAL. */
wgex_handle  wgex_test_packetfd_echo(int32_t fd, int32_t mtu);
/* Stops the echo; returns the number of packets echoed, or -1 for an unknown handle. */
int64_t      wgex_test_packetfd_echo_stop(wgex_handle h);

#ifdef __cplusplus
}
#endif
