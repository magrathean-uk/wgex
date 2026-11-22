// SPDX-License-Identifier: MIT

// CWGEXSysShim: see include/CWGEXSysShim.h. MIT, part of WGEX.
#include "CWGEXSysShim.h"

#include <errno.h>
#include <TargetConditionals.h>
#include <string.h>

#if TARGET_OS_OSX
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>

static int wgex_ioctl(int fd, unsigned long request, void *argument) {
    if (argument == NULL) {
        return EINVAL;
    }
    return ioctl(fd, request, argument) == 0 ? 0 : errno;
}

int wgex_sioc_aifaddr_in6(int fd, void *in6_aliasreq) {
    return wgex_ioctl(fd, SIOCAIFADDR_IN6, in6_aliasreq);
}

int wgex_interface_mtu(int fd, const char *name, int mtu) {
    if (name == NULL || strlen(name) >= IFNAMSIZ || mtu < 576 || mtu > 1500) return EINVAL;
    struct ifreq request = {0};
    strlcpy(request.ifr_name, name, IFNAMSIZ);
    request.ifr_mtu = mtu;
    return wgex_ioctl(fd, SIOCSIFMTU, &request);
}

int wgex_interface_address(int fd, const char *name, const uint8_t *address, int length, int prefix, int remove) {
    if (name == NULL || address == NULL || strlen(name) >= IFNAMSIZ ||
        (length != 4 && length != 16) || prefix < 0 || prefix > length * 8) return EINVAL;
    uint8_t mask[16] = {0};
    for (int bit = 0; bit < prefix; bit++) mask[bit / 8] |= (uint8_t)(0x80 >> (bit % 8));
    if (length == 4) {
        struct ifaliasreq request = {0};
        strlcpy(request.ifra_name, name, IFNAMSIZ);
        struct sockaddr_in *addr = (struct sockaddr_in *)&request.ifra_addr;
        struct sockaddr_in *netmask = (struct sockaddr_in *)&request.ifra_mask;
        addr->sin_len = sizeof(*addr); addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr, address, 4);
        /* utun is point-to-point: ifra_broadaddr is the destination alias. */
        request.ifra_broadaddr = request.ifra_addr;
        netmask->sin_len = sizeof(*netmask); netmask->sin_family = AF_INET;
        memcpy(&netmask->sin_addr, mask, 4);
        return wgex_ioctl(fd, remove ? SIOCDIFADDR : SIOCAIFADDR, &request);
    }
    struct in6_aliasreq request = {0};
    strlcpy(request.ifra_name, name, IFNAMSIZ);
    request.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
    request.ifra_addr.sin6_family = AF_INET6;
    memcpy(&request.ifra_addr.sin6_addr, address, 16);
    request.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
    request.ifra_prefixmask.sin6_family = AF_INET6;
    memcpy(&request.ifra_prefixmask.sin6_addr, mask, 16);
    request.ifra_lifetime.ia6t_vltime = 0xffffffff;
    request.ifra_lifetime.ia6t_pltime = 0xffffffff;
    if (remove) {
        struct in6_ifreq deletion = {0};
        strlcpy(deletion.ifr_name, name, IFNAMSIZ);
        deletion.ifr_addr = request.ifra_addr;
        return wgex_ioctl(fd, SIOCDIFADDR_IN6, &deletion);
    }
    return wgex_sioc_aifaddr_in6(fd, &request);
}
#else
int wgex_sioc_aifaddr_in6(int fd, void *in6_aliasreq) {
    (void)fd;
    (void)in6_aliasreq;
    return ENOTSUP;
}

int wgex_interface_mtu(int fd, const char *name, int mtu) {
    (void)fd; (void)name; (void)mtu; return ENOTSUP;
}
int wgex_interface_address(int fd, const char *name, const uint8_t *address, int length, int prefix, int remove) {
    (void)fd; (void)name; (void)address; (void)length; (void)prefix; (void)remove; return ENOTSUP;
}
#endif
