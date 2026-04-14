extern "C"
{
#include <sys/types.h>
#include <sys/user.h>
#include <sys/sysctl.h>  // kinfo_proc and stuff

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>
}

#include "hen/include/shellcore_patches/1_00.h"
#include "hen/include/shellcore_patches/1_02.h"
#include "hen/include/shellcore_patches/1_12.h"
#include "hen/include/shellcore_patches/1_14.h"
#include "hen/include/shellcore_patches/2_00.h"
#include "hen/include/shellcore_patches/2_20.h"
#include "hen/include/shellcore_patches/2_25.h"
#include "hen/include/shellcore_patches/2_26.h"
#include "hen/include/shellcore_patches/2_30.h"
#include "hen/include/shellcore_patches/2_50.h"
#include "hen/include/shellcore_patches/2_70.h"
#include "hen/include/shellcore_patches/3_00.h"
#include "hen/include/shellcore_patches/3_10.h"
#include "hen/include/shellcore_patches/3_20.h"
#include "hen/include/shellcore_patches/3_21.h"
#include "hen/include/shellcore_patches/4_00.h"
#include "hen/include/shellcore_patches/4_02.h"
#include "hen/include/shellcore_patches/4_03.h"
#include "hen/include/shellcore_patches/4_50.h"
#include "hen/include/shellcore_patches/4_51.h"

#include "util.h"

static int file_exists(const char* path)
{
    if (access(path, F_OK) == 0)
    {
        return 1;
    }
    return 0;
}

static bool sceKernelIsTestKit(void) {
    return file_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}

static bool sceKernelIsDevKit(void) {
    return file_exists("/system/priv/lib/libSceDeci5Dtracep.sprx");
}

enum kit_type {
    KIT_RETAIL,
    KIT_TESTKIT,
    KIT_DEVKIT
};

static enum kit_type get_kit_type(void) {
    if (sceKernelIsDevKit()) return KIT_DEVKIT;
    if (sceKernelIsTestKit()) return KIT_TESTKIT;
    return KIT_RETAIL;
}


static void patchShellcore(pid_t pid)
{
    const char* test_file = "/system/priv/lib/libSceFsInternalForVsh.sprx";
    const int check_file = file_exists(test_file);
    print("%s: file exist check %s = %d\n", __FUNCTION__, test_file, check_file);
    if (!check_file)
    {
        print("%s: can't access %s! failed to pass kit test.\n", __FUNCTION__, test_file);
        return;
    }
    // Resolve patches for this fw
    struct patch* patches = 0;
    int num_patches = 0;
    const uint32_t fw_ver = g_fw();
    printf("%s: fw_ver = 0x%x\n", __FUNCTION__, fw_ver);

    enum kit_type kit = get_kit_type();
    
    if (kit == KIT_RETAIL)
        printf("[HEN] [SHELLCORE] kit=RETAIL\n");
    else if (kit == KIT_TESTKIT)
        printf("[HEN] [SHELLCORE] kit=TESTKIT\n");
    else if (kit == KIT_DEVKIT)
        printf("[HEN] [SHELLCORE] kit=DEVKIT\n");

    #define FW(x) \
        case 0x ## x:\
            switch (kit) { \
                case KIT_DEVKIT: \
                    patches = (struct patch*)&g_shellcore_patches_##x##_devkit; \
                    num_patches = sizeof(g_shellcore_patches_##x##_devkit)/sizeof(struct patch); \
                    break; \
                case KIT_TESTKIT: \
                    patches = (struct patch*)&g_shellcore_patches_##x##_testkit; \
                    num_patches = sizeof(g_shellcore_patches_##x##_testkit)/sizeof(struct patch); \
                    break; \
                case KIT_RETAIL: \
                    patches = (struct patch*)&g_shellcore_patches_##x##_retail; \
                    num_patches = sizeof(g_shellcore_patches_##x##_retail)/sizeof(struct patch); \
                    break; \
                } \
                break


    switch (fw_ver) {
    FW(100);
    FW(102);
    FW(112);
    FW(114);
    FW(200);
    FW(220);
    FW(225);
    FW(226);
    FW(230);
    FW(250);
    FW(270);
    FW(300);
    FW(310);
    FW(320);
    FW(321);
    FW(400);
    FW(403);
    FW(450);
    FW(451);
    default:
        printf("%s: don't have offsets for this firmware %x\n", __FUNCTION__, fw_ver);
        return;
    }
    #undef FW

    const uintptr_t shellcore_base_addr = kernel_dynlib_mapbase_addr(pid, 0);
    size_t patch_okay = 0;
    if (shellcore_base_addr)
    {
        for (int i = 0; i < num_patches; i++)
        {
            if (mdbg_copyin(pid, patches[i].data, shellcore_base_addr + patches[i].offset, patches[i].size) == 0)
            {
                patch_okay += 1;
            }
            else
            {
                printf("%s:  shellcore patch %d failed\n", __FUNCTION__, i + 1);
            }
        }
        printf("%s:  shellcore patch %ld applied\n", __FUNCTION__, patch_okay);
    }
}

int shellcore_patch()
{
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size;
    uint8_t* buf;

    // determine size of query response
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0))
    {
        perror("sysctl");
        return -(__LINE__);
    }

    // allocate memory for query response
    if (!(buf = (uint8_t*)malloc(buf_size)))
    {
        perror("malloc");
        return -(__LINE__);
    }

    // query the kernel for proc info
    if (sysctl(mib, 4, buf, &buf_size, NULL, 0))
    {
        perror("sysctl");
        free(buf);
        return -(__LINE__);
    }
    for (uint8_t* ptr = buf; ptr < (buf + buf_size);)
    {
        struct kinfo_proc* ki = (struct kinfo_proc*)ptr;
        ptr += ki->ki_structsize;
        if (strcmp(ki->ki_comm, "SceShellCore") == 0)
        {
            patchShellcore(ki->ki_pid);
            break;
        }
    }

    free(buf);
    return 0;
}
