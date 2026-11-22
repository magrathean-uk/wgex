// SPDX-License-Identifier: MIT
// Guest-only foreign-interface fixture. Never run this helper on the host.
#ifndef WGEX_LAB_BUILD
#error "foreign-utun requires the Lab build flag"
#endif
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/sys_domain.h>
#include <unistd.h>

int main(void) {
    // The guest VM check of guard.sh: macOS 26 or 27, the hypervisor sysctl, then the root-owned 0644 marker.
    int hypervisor = 0;
    size_t length = sizeof(hypervisor);
    char version[32] = {0};
    size_t version_length = sizeof(version) - 1;
    struct stat marker;
    if (geteuid() != 0 || sysctlbyname("kern.osproductversion", version, &version_length, NULL, 0) != 0 ||
        (strncmp(version, "26.", 3) != 0 && strncmp(version, "27.", 3) != 0) ||
        sysctlbyname("kern.hv_vmm_present", &hypervisor, &length, NULL, 0) != 0 || hypervisor != 1 ||
        lstat("/var/db/wgex-lab-host", &marker) != 0 || !S_ISREG(marker.st_mode) || marker.st_uid != 0 ||
        (marker.st_mode & 0777) != 0644) {
        fputs("foreign-utun: guarded root guest required\n", stderr);
        return 1;
    }
    int descriptor = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (descriptor < 0) return 2;
    struct ctl_info control = {0};
    (void)snprintf(control.ctl_name, sizeof(control.ctl_name), "com.apple.net.utun_control");
    if (ioctl(descriptor, CTLIOCGINFO, &control) != 0) { close(descriptor); return 3; }
    struct sockaddr_ctl address = {0};
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = control.ctl_id;
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) { close(descriptor); return 4; }
    char name[IFNAMSIZ] = {0};
    socklen_t name_length = sizeof(name);
    if (getsockopt(descriptor, SYSPROTO_CONTROL, 2, name, &name_length) != 0) { close(descriptor); return 5; }
    puts(name);
    fflush(stdout);
    for (;;) pause(); // SIGTERM closes the descriptor and destroys only this fixture.
}
