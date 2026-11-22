// SPDX-License-Identifier: MIT

// CWGEXSysShim: plain functions for the function-like ioctl request macros
// Swift cannot import (02 §2). MIT, part of WGEX.
#pragma once

#include <net/if.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// ABI version of this shim.
enum { WGEX_SYSSHIM_ABI_VERSION = 1 };

/// SIOCAIFADDR_IN6 on `fd` with a `struct in6_aliasreq` (from <netinet6/in6_var.h>,
/// macOS only, hence `void *`). Returns 0 or an errno value (ENOTSUP outside macOS).
int wgex_sioc_aifaddr_in6(int fd, void *in6_aliasreq);

/// Address request builder and ioctl; caller supplies an already-open, guarded control descriptor.
/// `address` is exactly 4 or 16 network-order octets. No socket is opened by this shim.
int wgex_interface_address(int fd, const char *name, const uint8_t *address, int length, int prefix, int remove);
int wgex_interface_mtu(int fd, const char *name, int mtu);

#ifdef __cplusplus
}
#endif
