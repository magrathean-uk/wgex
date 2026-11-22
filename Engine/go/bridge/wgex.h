// SPDX-License-Identifier: MIT

// WGEX engine C ABI (module CWGEXEngine), 02-architecture §6.2. Hand-written;
// the header cgo generates is discarded by Engine/scripts/build-xcframework.sh.
// Every function declared here is exported by the archive and vice versa
// (bridge/abi_test.go checks the names).
//
// Rules:
// - No function waits on the network, except wgex_resolve, which is a
//   bounded DNS lookup (servers x 2 attempts x timeout) and must be called
//   off the main thread.
// - Callbacks run on one engine-owned Go thread per engine, never under an
//   engine lock; msg/json are not NUL-terminated and valid only for the call.
//   A callback must not block waiting for another engine call to finish.
// - wgex_destroy returns only when no callback of that engine is in flight.
//   Called from inside a callback (any engine's), it cannot wait for the
//   running callback: it starts the teardown, returns WGEX_OK at once, and no
//   further callback of that engine starts after the current one returns.
// - UAPI documents are read as bytes for the duration of the call and never
//   become Go strings in WGEX code; the caller may wipe them on return. The
//   engine keeps its own copy of the last good full document (wiped when
//   superseded and on destroy) so it can restore it.
// - No package-global logger, no init side effects, no signal handlers.
#pragma once
#include <stdint.h>
#include <stddef.h>

#define WGEX_ABI_VERSION 2

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t wgex_handle;                 /* > 0 valid; < 0 error code */

typedef enum {
    WGEX_OK = 0,
    WGEX_EINVAL = -1,     /* bad argument or document shape; nothing changed */
    WGEX_ENOMEM = -2,
    WGEX_EHANDLE = -3,    /* unknown or destroyed handle */
    WGEX_ETUN = -4,       /* tun device could not be created */
    WGEX_EBIND = -5,      /* sockets could not be bound */
    WGEX_ECONFIG = -6,    /* full configuration restored after rejection, or endpoint update rejected (no rollback promise) */
    WGEX_EUP = -7,
    WGEX_ESTATE = -8,     /* operation not valid in this state */
    WGEX_EDEVICECLOSED = -9, /* fatal: device closed; destroy this handle and create a new engine */
    WGEX_EINTERNAL = -99
} wgex_error_t;

/* Event kinds; the JSON payload repeats the name in "kind". Times are RFC 3339 UTC
   with nanoseconds; peers are standard-base64 public keys. */
typedef enum {
    WGEX_EVENT_ENGINE = 0,              /* {"kind":"engine","event":"socketsBumped"|"transportChanged"|"configRestored"|"deviceClosed",...} deviceClosed reason: 1 tun read/unsolicited close, 2 config rejected */
    WGEX_EVENT_HANDSHAKE_COMPLETED = 1, /* {"kind":"handshakeCompleted","peer":..,"at":..} */
    WGEX_EVENT_TX_WITHOUT_RX = 2,       /* {"kind":"txWithoutRx","peer":..,"since":..,"window":n}: n-th 15 s window */
    WGEX_EVENT_RX = 3,                  /* {"kind":"rx","at":..}: at most one per 5 s */
    WGEX_EVENT_ENDPOINT_CHANGED = 4,    /* {"kind":"endpointChanged","peer":..,"endpoint":"ip:port"} */
    WGEX_EVENT_TRANSPORT = 5            /* carrier events (phase 6) */
} wgex_event_kind_t;

/* Log levels: 0 debug, 1 info, 2 error. */
typedef void (*wgex_log_fn)(void *ctx, int32_t level, const char *msg, size_t len);
typedef void (*wgex_event_fn)(void *ctx, int32_t kind, const char *json, size_t len);

typedef struct {
    int32_t     tun_kind;          /* 0 = NE utun fd (mtu must be 0), 1 = packet fd (SOCK_DGRAM
                                      socketpair end), 2 = create utun (root) */
    int32_t     tun_fd;            /* kinds 0 and 1; duplicated, the caller keeps its descriptor.
                                      The descriptor is switched to non-blocking mode. */
    const char *tun_name;          /* kind 2: "utun" (auto-assign) or "utunN"; NULL otherwise */
    int32_t     mtu;               /* kinds 1 (576...65535) and 2 */
    int32_t     bind_ifindex_v4;   /* 0 = unbound */
    int32_t     bind_ifindex_v6;   /* 0 = unbound */
    const char *transport_json;    /* TransportSpec; NULL or {"kind":"udp"}; anything else -> WGEX_EINVAL */
    int32_t     mobile_quirks;     /* 1 on iOS/tvOS: DisableSomeRoamingForBrokenMobileSemantics after each apply */
    wgex_log_fn log;   void *log_ctx;
    wgex_event_fn event; void *event_ctx;
    int32_t log_level;             /* 0 default/info, 1 debug, 2 error, 3 off; gated before formatting */
} wgex_create_params;

/* Process-wide settings. memory_limit_bytes 0 = runtime default; gc_percent 0 = default,
   -1 = GC off; queue_profile 0 = default, 1 = constrained (256-deep queues and pools; applies
   under GOOS=ios only, wireguard-go queue sizes are constants on macOS). Applied immediately
   and only before the first wgex_create; a repeat with identical values returns WGEX_OK,
   different values or a call after an engine was created return WGEX_ESTATE. */
typedef struct { int64_t memory_limit_bytes; int32_t gc_percent; int32_t queue_profile; } wgex_process_params;
int32_t      wgex_abi_version(void);
int32_t      wgex_configure_process(const wgex_process_params *p);

wgex_handle  wgex_create(const wgex_create_params *p);
/* Full replace: replace_peers=true is required. WGEX_ECONFIG means a previous
   full configuration was restored. A first configuration has nothing to restore;
   an unrecoverable apply or failed restoration returns WGEX_EDEVICECLOSED.
   Argument validation returns WGEX_EINVAL without changing the device. */
int32_t      wgex_set_config(wgex_handle h, const uint8_t *uapi, size_t len);
/* Only public_key / update_only=true / endpoint lines; sessions are kept. */
int32_t      wgex_update_endpoints(wgex_handle h, const uint8_t *uapi, size_t len);
/* Up and SetConfiguration return WGEX_EDEVICECLOSED after device closure. */
int32_t      wgex_up(wgex_handle h);
/* Idempotent on a closed device: already closed means already down (WGEX_OK).
   A destroyed handle still returns WGEX_EHANDLE. */
int32_t      wgex_down(wgex_handle h);
/* Idempotent; see the callback rule above. */
int32_t      wgex_destroy(wgex_handle h);
/* Returns at once; rebinds in the background (BindUpdate up to 10 x 500 ms, then keepalives),
   cancelling a previous attempt. The outcome arrives as an engine event "socketsBumped". */
int32_t      wgex_bump_sockets(wgex_handle h, int32_t ifindex_v4, int32_t ifindex_v6);
/* Only {"kind":"udp"} until phase 6 (udp -> udp rebinds on the same port); else WGEX_EINVAL. */
int32_t      wgex_set_transport(wgex_handle h, const char *transport_json, size_t len);
/* Per peer: ExpireCurrentKeypairs + SendHandshakeInitiation; no peer replacement. */
int32_t      wgex_force_handshake(wgex_handle h);
/* iOS/tvOS: descriptor scan for the NE utun socket; -1 if none and always -1 on macOS. */
int32_t      wgex_find_utun_fd(void);
/* {"interface_name","listen_port","sampled_at","peers":[{"public_key","endpoint",
   "last_handshake_time","rx_bytes","tx_bytes","persistent_keepalive_interval"}]};
   never a private or preshared key. NULL on error. Free with wgex_free. */
char        *wgex_public_stats_json(wgex_handle h);
/* Valid until wgex_destroy; NULL if unknown. Do not free. */
const char  *wgex_tun_name(wgex_handle h);
int32_t      wgex_free_os_memory(void);
/* UnderlayResolver: A and AAAA over UDP (TCP fallback) from sockets bound to the given
   interfaces (0 = unbound). resolvers_json: ["ip" | "ip:port" | "[v6]:port", ...] or
   {"servers":[...],"timeout_ms":n} (default 2000 per attempt). Returns
   {"a":[...],"aaaa":[...],"ttl":n[,"error":"invalid"|"nxdomain"|"nodata"|"failed"]};
   free with wgex_free. Blocks for at most servers x 2 x timeout. */
char        *wgex_resolve(const char *host, int32_t ifindex_v4, int32_t ifindex_v6, const char *resolvers_json);

/* Frees memory the engine allocated for the caller. NULL is accepted. */
void         wgex_free(void *p);
/* Static JSON {app_version, build, engine_commit, go, script_sha}, valid for the life of the
   process. Do not pass it to wgex_free. */
const char  *wgex_build_info(void);

#ifdef __cplusplus
}
#endif
