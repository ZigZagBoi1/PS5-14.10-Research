/* Modern Relapse elfldr enters through the PS5 Payload SDK CRT. */
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <ps5/kernel.h>
int payload_main(void *args);
static pid_t research_getpid(void) {
    long result = 20;
    __asm__ volatile("syscall" : "+a"(result) :: "rcx", "r11", "memory", "cc");
    return (pid_t)result;
}
static uint64_t saved_authid;
static uint8_t saved_caps[16];
static uint32_t saved_uid;
static uint32_t saved_ruid;
static uint8_t saved_attrs[32];
static int privileges_changed;
static int used_updater_identity;
int research_used_updater_identity(void) { return used_updater_identity; }
static pid_t research_find_updater(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) || !size) return -1;
    char *buffer = malloc(size);
    if (!buffer) return -1;
    pid_t found = -1;
    if (!sysctl(mib, 4, buffer, &size, NULL, 0)) {
        for (char *p = buffer; p < buffer + size;) {
            struct kinfo_proc *ki = (struct kinfo_proc *)p;
            if (ki->ki_structsize < sizeof(int) || p + ki->ki_structsize > buffer + size) break;
            if (strstr(ki->ki_comm, "SceUpdatePupUtil")) {
                found = ki->ki_pid;
                break;
            }
            p += ki->ki_structsize;
        }
    }
    free(buffer);
    return found;
}
int research_privileges_end(void);
int research_privileges_begin(void) {
    const pid_t pid = research_getpid();
    const uint8_t full_caps[16] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    saved_authid = kernel_get_ucred_authid(pid);
    if (!saved_authid || kernel_get_ucred_caps(pid, saved_caps)) return -1;
    saved_uid = kernel_get_ucred_uid(pid);
    saved_ruid = kernel_get_ucred_ruid(pid);
    if (kernel_get_ucred_attrs(pid, saved_attrs)) return -1;
    pid_t updater_pid = research_find_updater();
    uint64_t target_authid = 0x4800000000010003ULL;
    uint8_t target_caps[16];
    uint8_t target_attrs[32];
    used_updater_identity = 0;
    if (updater_pid > 0 &&
        (target_authid = kernel_get_ucred_authid(updater_pid)) &&
        !kernel_get_ucred_caps(updater_pid, target_caps) &&
        !kernel_get_ucred_attrs(updater_pid, target_attrs)) {
        used_updater_identity = 1;
    } else {
        target_authid = 0x4800000000010003ULL;
    }
    if (kernel_set_ucred_authid(pid, target_authid)) return -2;
    privileges_changed = 1;
    if (kernel_set_ucred_caps(pid, used_updater_identity ? target_caps : full_caps)) {
        kernel_set_ucred_authid(pid, saved_authid);
        privileges_changed = 0;
        return -3;
    }
    if (used_updater_identity && kernel_set_ucred_attrs(pid, target_attrs)) {
        research_privileges_end();
        return -5;
    }
    if (kernel_set_ucred_uid(pid, 0) || kernel_set_ucred_ruid(pid, 0)) {
        research_privileges_end();
        return -4;
    }
    return 0;
}
int research_privileges_end(void) {
    if (!privileges_changed) return 0;
    const pid_t pid = research_getpid();
    int uid_result = kernel_set_ucred_uid(pid, saved_uid);
    int ruid_result = kernel_set_ucred_ruid(pid, saved_ruid);
    int attr_result = kernel_set_ucred_attrs(pid, saved_attrs);
    int cap_result = kernel_set_ucred_caps(pid, saved_caps);
    int auth_result = kernel_set_ucred_authid(pid, saved_authid);
    privileges_changed = 0;
    return (uid_result || ruid_result || attr_result || cap_result || auth_result) ? -1 : 0;
}
int sceKernelDlsym(int handle, const char *name, void **out);
int research_sdk_dlsym(int handle, const char *name, void *out) {
    void *address = dlsym(RTLD_DEFAULT, name);
    if (!address && handle > 0) {
        sceKernelDlsym(handle, name, &address);
    }
    if (!address && strcmp(name, "sceKernelLoadStartModule") == 0) {
        extern int sceKernelLoadStartModule(const char *, size_t, const void *,
                                           size_t, const void *, void *);
        address = (void *)sceKernelLoadStartModule;
    }
    *(void **)out = address;
    return address ? 0 : -1;
}
void research_stage(const char *message) {
    FILE *marker = fopen("/data/pup14-sdk-collector-entry-20261020.txt", "ab");
    if (marker) {
        fputs(message, marker);
        fputs("\n", marker);
        fclose(marker);
    }
}

int main(void) {
    FILE *marker = fopen("/data/pup14-sdk-collector-entry-20261020.txt", "wb");
    if (marker) {
        fputs("SDK collector entry reached\n", marker);
        fclose(marker);
    }
    return payload_main((void *)0);
}
