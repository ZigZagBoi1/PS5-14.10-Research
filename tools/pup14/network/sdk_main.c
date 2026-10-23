#include "defines.h"
#include "debug.h"
#include "resolve.h"

// https://github.com/OSM-Made/PS4-Notify
void printf_notification(const char* fmt, ...) {
    if (!f_vsprintf || !f_strcpy || !f_sceKernelSendNotificationRequest) return;
    SceNotificationRequest noti_buffer;

    va_list args;
    va_start(args, fmt);
    f_vsprintf(noti_buffer.message, fmt, args);
    va_end(args);

    noti_buffer.type = 0;
    noti_buffer.unk3 = 0;
    noti_buffer.use_icon_image_uri = 1;
    noti_buffer.target_id = -1;
    f_strcpy(noti_buffer.uri, "cxml://psnotification/tex_icon_system");

    f_sceKernelSendNotificationRequest(0, (SceNotificationRequest * ) & noti_buffer, sizeof(noti_buffer), 0);
}


int decrypt_pups(const char *input_path, const char *output_path);

int sock;
void research_stage(const char *message);
int research_privileges_begin(void);
int research_privileges_end(void);
int research_used_updater_identity(void);


/* The SDK CRT adapts the Relapse loader ABI and supplies sceKernelDlsym. */
int research_sdk_dlsym(int handle, const char *name, void *out);
static int research_dlsym(int handle, const char *name, void *out) {
    return research_sdk_dlsym(handle, name, out);
}
static void research_raw_write(const char *message, unsigned long length) {
    long result = 4;
    __asm__ volatile("syscall" : "+a"(result)
                     : "D"(1L), "S"(message), "d"(length)
                     : "rcx", "r11", "memory", "cc");
}

int payload_main(struct payload_args *args) {
    (void)args;
    dlsym_t* dlsym = research_dlsym;
	
	
	
	int libKernel = 0x2001;

    dlsym(libKernel, "sceKernelLoadStartModule", &f_sceKernelLoadStartModule);
    if (!f_sceKernelLoadStartModule) {
        research_stage("kernel symbol resolution failed");
        research_raw_write("PUP research: symbol resolution failed\n", 39);
        return -1;
    }
	dlsym(libKernel, "sceKernelDebugOutText", &f_sceKernelDebugOutText);
	dlsym(libKernel, "sceKernelSendNotificationRequest", &f_sceKernelSendNotificationRequest);
	dlsym(libKernel, "sceKernelUsleep", &f_sceKernelUsleep);
	dlsym(libKernel, "scePthreadMutexLock", &f_scePthreadMutexLock);
	dlsym(libKernel, "scePthreadMutexUnlock", &f_scePthreadMutexUnlock);
	dlsym(libKernel, "scePthreadExit", &f_scePthreadExit);
	dlsym(libKernel, "scePthreadMutexInit", &f_scePthreadMutexInit);
	dlsym(libKernel, "scePthreadCreate", &f_scePthreadCreate);
	dlsym(libKernel, "scePthreadMutexDestroy", &f_scePthreadMutexDestroy);
	dlsym(libKernel, "scePthreadJoin", &f_scePthreadJoin);
	dlsym(libKernel, "socket", &f_socket);
	dlsym(libKernel, "bind", &f_bind);
	dlsym(libKernel, "listen", &f_listen);
	dlsym(libKernel, "accept", &f_accept);
	dlsym(libKernel, "ioctl", &f_ioctl);
	dlsym(libKernel, "open", &f_open);
	dlsym(libKernel, "read", &f_read);
	dlsym(libKernel, "write", &f_write);
	dlsym(libKernel, "close", &f_close);
	dlsym(libKernel, "stat", &f_stat);
	dlsym(libKernel, "fstat", &f_fstat);
	dlsym(libKernel, "rename", &f_rename);
	dlsym(libKernel, "rmdir", &f_rmdir);
	dlsym(libKernel, "mkdir", &f_mkdir);
	dlsym(libKernel, "getdents", &f_getdents);
	dlsym(libKernel, "unlink", &f_unlink);
	dlsym(libKernel, "readlink", &f_readlink);
	dlsym(libKernel, "lseek", &f_lseek);
	dlsym(libKernel, "puts", &f_puts);
	dlsym(libKernel, "mmap", &f_mmap);
	dlsym(libKernel, "munmap", &f_munmap);
	dlsym(libKernel, "__error", &f___error);
	

	int libNet = f_sceKernelLoadStartModule("libSceNet.sprx", 0, 0, 0, 0, 0);
    research_stage("libSceNet module load returned");
	dlsym(libNet, "sceNetSocket", &f_sceNetSocket);
	dlsym(libNet, "sceNetConnect", &f_sceNetConnect);
	dlsym(libNet, "sceNetHtons", &f_sceNetHtons);
	dlsym(libNet, "sceNetAccept", &f_sceNetAccept);
	dlsym(libNet, "sceNetSend", &f_sceNetSend);
	dlsym(libNet, "sceNetInetNtop", &f_sceNetInetNtop);
	dlsym(libNet, "sceNetSocketAbort", &f_sceNetSocketAbort);
	dlsym(libNet, "sceNetBind", &f_sceNetBind);
	dlsym(libNet, "sceNetListen", &f_sceNetListen);
	dlsym(libNet, "sceNetSocketClose", &f_sceNetSocketClose);
	dlsym(libNet, "sceNetHtonl", &f_sceNetHtonl);
	dlsym(libNet, "sceNetInetPton", &f_sceNetInetPton);
	dlsym(libNet, "sceNetGetsockname", &f_sceNetGetsockname);
	dlsym(libNet, "sceNetRecv", &f_sceNetRecv);
	dlsym(libNet, "sceNetErrnoLoc", &f_sceNetErrnoLoc);
	dlsym(libNet, "sceNetSetsockopt", &f_sceNetSetsockopt);

	int libC = f_sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, 0, 0, 0, 0);
	dlsym(libC, "vsprintf", &f_vsprintf);
	dlsym(libC, "memset", &f_memset);
	dlsym(libC, "memalign", &f_memalign);
	dlsym(libC, "sprintf", &f_sprintf);
	dlsym(libC, "snprintf", &f_snprintf);
	dlsym(libC, "snprintf_s", &f_snprintf_s);
	dlsym(libC, "strcat", &f_strcat);
	dlsym(libC, "free", &f_free);
	dlsym(libC, "memcpy", &f_memcpy);
	dlsym(libC, "strcpy", &f_strcpy);
	dlsym(libC, "strncpy", &f_strncpy);
	dlsym(libC, "sscanf", &f_sscanf);
	dlsym(libC, "malloc", &f_malloc);
	dlsym(libC, "calloc", &f_calloc);
	dlsym(libC, "strlen", &f_strlen);
	dlsym(libC, "strcmp", &f_strcmp);
	dlsym(libC, "strchr", &f_strchr);
	dlsym(libC, "strrchr", &f_strrchr);
	dlsym(libC, "gmtime_s", &f_gmtime_s);
	dlsym(libC, "time", &f_time);
	dlsym(libC, "localtime", &f_localtime);
	dlsym(libC, "strerror", &f_strerror);
	
	int libNetCtl = f_sceKernelLoadStartModule("libSceNetCtl.sprx", 0, 0, 0, 0, 0);
	dlsym(libNetCtl, "sceNetCtlInit", &f_sceNetCtlInit);
	dlsym(libNetCtl, "sceNetCtlTerm", &f_sceNetCtlTerm);
	dlsym(libNetCtl, "sceNetCtlGetInfo", &f_sceNetCtlGetInfo);


    if (!f_sceNetSocket || !f_sceNetConnect || !f_sceNetHtons ||
        !f_sceNetSocketClose || !f_sceNetSend || !f_sceNetRecv ||
        !f_memset || !f_memcpy || !f_memalign || !f_malloc || !f_free ||
        !f_open || !f_close || !f_ioctl || !f_snprintf || !f_sprintf || !f_strlen) {
        research_stage("required import missing");
        research_raw_write("PUP research: required import missing\n", 38);
        return -1;
    }
    research_stage("network symbols resolved");
    int connect_result = research_net_connect();
    research_stage(connect_result == 0 ? "network connected" : "network connect failed");
    if (connect_result != 0) {
        char error_message[128];
        int net_error = f_sceNetErrnoLoc ? *f_sceNetErrnoLoc() : -1;
        f_snprintf(error_message, sizeof(error_message),
                   "PUP research: network connect failed (%d), errno=%d\n", connect_result, net_error);
        research_raw_write(error_message, f_strlen(error_message));
        printf_notification("PUP research: server connection failed");
        return -1;
    }
    printfsocket("PS5 14.10 full PUP extraction over LAN; no updater API\n");
    printf_notification("PUP research extraction started");
    int privilege_result = research_privileges_begin();
    printfsocket("Temporary privilege setup: %d updater_identity=%d\n",
                 privilege_result, research_used_updater_identity());
    int result = privilege_result == 0 ? decrypt_pups(INPUTPATH, OUTPUTPATH) : -1;
    int restore_result = research_privileges_end();
    printfsocket("Privilege restore: %d\n", restore_result);
    printfsocket(result == 0 ? "RESEARCH EXTRACTION SUCCESS\n" : "RESEARCH EXTRACTION FAILED\n");
    research_net_finish(result == 0);
    research_net_close();
    printf_notification(result == 0 ? "PUP extraction sent to server" : "PUP extraction failed: check server log");
    return result;
}
