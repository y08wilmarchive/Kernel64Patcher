/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "patchfinder64.c"
#include "patchfinder64_friedappleteam.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)
#define GET_OFFSET2(kernel_len, x) (x + (uintptr_t) kernel_buf)

#define LSL0 0
#define LSL16 16
#define LSL32 32

#define _PAGEOFF(x) ((x) & 0xFFFFF000)

#define _ADRP(r, o) (0x90000000 | ((((o) >> 12) & 0x3) << 29) | ((((o) >> 12) & 0x1FFFFC) << 3) | ((r) & 0x1F))
#define _BL(a, o) (0x94000000 | ((((o) - (a)) >> 2) & 0x3FFFFFF))
#define _B(a, o) (0x14000000 | ((((o) - (a)) >> 2) & 0x3FFFFFF))
#define _MOVKX(r, i, s) (0xF2800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _MOVZX(r, i, s) (0xD2800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _MOVZW(r, i, s) (0x52800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _NOP() 0xD503201F

// iOS 7 arm64
int get_vm_map_enter_patch_ios7(void* kernel_buf,size_t kernel_len) {
    // search 0A 05 1F 12 09 79 1D 12
    //AND             w9, w8, #0xfffffffb
    uint8_t search[] = { 0x0A, 0x05, 0x1F, 0x12, 0x09, 0x79, 0x1D, 0x12 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    // mov w9, w8 is 0xE9 0x03 0x08 0x2A which translates to 2a0803e9 in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x2A0803E9; // mov w9, w8
    return 0;
}

// iOS 8 arm64
int get_vm_map_enter_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 49 01 09 2A 0A 79 1D 12
    //AND             W10, W8, #0xFFFFFFFB
    uint8_t search[] = { 0x49, 0x01, 0x09, 0x2A, 0x0A, 0x79, 0x1D, 0x12 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w10, w8 not a nop
    // mov w10, w8 is 0xEA 0x03 0x08 0x2A which translates to 2a0803ea in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x2A0803EA; // mov w10, w8
    return 0;
}

// iOS 8 arm64
int get_vm_map_protect_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search EA 17 9F 1A 6A 01 0A 0A CB 7A 1D 12
    // ea179f1a6a010a0acb7a1d12
    // cset w10, eq
    // and w10, w11, w10
    // and w11, w22, #0xfffffffb
    uint8_t search[] = { 0xEA, 0x17, 0x9F, 0x1A, 0x6A, 0x01, 0x0A, 0x0A, 0xCB, 0x7A, 0x1D, 0x12 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_protect\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_protect\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_protect\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_protect\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_protect patch needs to be mov w11, w22 not a nop
    // mov w11, w22 is 0xEB 0x03 0x16 0x2A which translates to 2a1603eb in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4 + 0x4) = 0x2A1603EB;
    return 0;
}

// iOS 9 arm64
int get_vm_map_enter_patch_ios9(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1D 12 1F 01 1E 72 09 01 89 1A DF 02 00 71 09 11 89 1A 1F 01 1F 72
    // and w9, w8, #0xfffffffb -> mov w9, w8
    // tst w8, #0x4
    // csel w9, w8, w9, eq
    // cmp w22, #0
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    uint8_t search[] = { 0x09, 0x79, 0x1D, 0x12, 0x1F, 0x01, 0x1E, 0x72, 0x09, 0x01, 0x89, 0x1A, 0xDF, 0x02, 0x00, 0x71, 0x09, 0x11, 0x89, 0x1A, 0x1F, 0x01, 0x1F, 0x72 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 9 arm64
int get_vm_map_protect_patch_ios9(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1D 12 1F 01 1E 72 09 01 89 1A 7F 01 00 71 09 11 89 1A 1F 01 1F 72
    // and w9, w8, #0xfffffffb -> mov w9, w8
    // tst w8, #0x4
    // csel w9, w8, w9, eq
    // cmp w11, #0
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    uint8_t search[] = { 0x09, 0x79, 0x1D, 0x12, 0x1F, 0x01, 0x1E, 0x72, 0x09, 0x01, 0x89, 0x1A, 0x7F, 0x01, 0x00, 0x71, 0x09, 0x11, 0x89, 0x1A, 0x1F, 0x01, 0x1F, 0x72 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_protect\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_protect\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_protect\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_protect\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_protect patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 11 arm64
int get_vm_map_enter_patch_ios11(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1d 12 09 11 89 1a 1f 01 1f 72 11 01 89 1a
    // and w9, w8, #0xfffffffb
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    // csel w17, w8, w9, eq
    uint8_t search[] = { 0x09, 0x79, 0x1d, 0x12, 0x09, 0x11, 0x89, 0x1a, 0x1f, 0x01, 0x1f, 0x72, 0x11, 0x01, 0x89, 0x1a };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 11 arm64
int get_vm_map_protect_patch_ios11(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1d 12 09 11 89 1a 1f 01 1f 72 1c 01 89 1a
    // and w9, w8, #0xfffffffb
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    // csel w28, w8, w9, eq
    uint8_t search[] = { 0x09, 0x79, 0x1d, 0x12, 0x09, 0x11, 0x89, 0x1a, 0x1f, 0x01, 0x1f, 0x72, 0x1c, 0x01, 0x89, 0x1a };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_protect\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_protect\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_protect\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_protect\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_protect patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 10 arm64
int get_vm_map_enter_patch_ios10(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1d 12 09 11 89 1a 1f 01 1f 72 09 01 89 1a
    // and w9, w8, #0xfffffffb -> mov w9, w8
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    // csel w9, w8, w9, eq
    uint8_t search[] = { 0x09, 0x79, 0x1d, 0x12, 0x09, 0x11, 0x89, 0x1a, 0x1f, 0x01, 0x1f, 0x72, 0x09, 0x01, 0x89, 0x1a };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 10 arm64
int get_vm_map_protect_patch_ios10(void* kernel_buf,size_t kernel_len) {
    // search 09 79 1d 12 09 11 89 1a 1f 01 1f 72 10 01 89 1a
    // and w9, w8, #0xfffffffb -> mov w9, w8
    // csel w9, w8, w9, ne
    // tst w8, #0x2
    // csel w16, w8, w9, eq
    uint8_t search[] = { 0x09, 0x79, 0x1d, 0x12, 0x09, 0x11, 0x89, 0x1a, 0x1f, 0x01, 0x1f, 0x72, 0x10, 0x01, 0x89, 0x1a };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_map_protect\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_map_protect\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_map_protect\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_protect\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_protect patch needs to be mov w9, w8 not a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x2a0803e9; // mov w9, w8
    return 0;
}

// iOS 7 arm64
int get_mount_common_patch_ios7(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 29 03 10 32 F5 03 00 32 39 01 88 1A
    // ORR             w9, w25, #0x10000
    // ORR             w21, wzr, #0x1
    // CSEL            w25, w9, w8, eq
    // add 0x8 to address
    uint8_t search[] = { 0x29, 0x03, 0x10, 0x32, 0xF5, 0x03, 0x00, 0x32, 0x39, 0x01, 0x88, 0x1A };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"mount_common\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mount_common\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"mount_common\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // add 0x8 to address https://github.com/TheRealClarity/wtfis/blob/main/wtfis/patchfinder64.c#L2121
    xref_stuff = xref_stuff + 0x8;
    // add 0x4 to address bcz we have 3 lines of arm64 instead of 2 lines of arm64
    xref_stuff = xref_stuff + 0x4;
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

// iOS 8 arm64
int get_mount_common_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 89 02 10 32 34 01 88 1A
    // ORR             W9, W20, #0x10000
    // CSEL            W20, W9, W8, EQ
    // add 0x8 to address
    uint8_t search[] = { 0x89, 0x02, 0x10, 0x32, 0x34, 0x01, 0x88, 0x1A };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"mount_common\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mount_common\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"mount_common\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // add 0x8 to address https://github.com/TheRealClarity/wtfis/blob/main/wtfis/patchfinder64.c#L2121
    xref_stuff = xref_stuff + 0x8;
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

// iOS 9 arm64
int get_mount_common_patch_ios9(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search E8 6E 40 F9 08 E5 41 39
    // ldr x8, [x23, #0xd8]
    // ldrb w8, [x8, #0x79]
    // add 0x4 to address
    uint8_t search[] = { 0xE8, 0x6E, 0x40, 0xF9, 0x08, 0xE5, 0x41, 0x39 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"mount_common\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mount_common\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"mount_common\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x4;
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x528000c8; // mov w8, 0x6
    return 0;
}

// iOS 10 arm64
int get_mount_common_patch_ios10(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search e8 6e 40 f9 08 c5 41 39
    // ldr x8, [x23, #0xd8]
    // ldrb w8, [x8, #0x71]
    // add 0x4 to address
    uint8_t search[] = { 0xe8, 0x6e, 0x40, 0xf9, 0x08, 0xc5, 0x41, 0x39 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"mount_common\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mount_common\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"mount_common\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x4;
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x528000c8; // mov w8, 0x6
    return 0;
}

// iOS 8 NoMoreSIGABRT
int get_NoMoreSIGABRT_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 48 58 00 05 80 00 21 00
    // add 0x4 to address to get 0x80 0x00 0x21 0x00
    uint8_t search[] = { 0x48, 0x58, 0x00, 0x05, 0x80, 0x00, 0x21, 0x00 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"NoMoreSIGABRT\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"NoMoreSIGABRT\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"NoMoreSIGABRT\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"NoMoreSIGABRT\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x2100c0 is 0xC0 0x00 0x21 0x00
    // we are replacing 0x80 0x00 0x21 0x00 with 0xC0 0x00 0x21 0x00
    // see https://nyansatan.github.io/dualboot/modifyingfilesystems.html for more info
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x2100c0;
    return 0;
}

// iOS 8 undo_NoMoreSIGABRT
int get_undo_NoMoreSIGABRT_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 48 58 00 05 C0 00 21 00
    // add 0x4 to address to get 0xC0 0x00 0x21 0x00
    uint8_t search[] = { 0x48, 0x58, 0x00, 0x05, 0xC0, 0x00, 0x21, 0x00 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"undo_NoMoreSIGABRT\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"undo_NoMoreSIGABRT\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"undo_NoMoreSIGABRT\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"undo_NoMoreSIGABRT\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x210080 is 0x80 0x00 0x21 0x00
    // we are replacing 0xC0 0x00 0x21 0x00 with 0x80 0x00 0x21 0x00
    // see https://nyansatan.github.io/dualboot/modifyingfilesystems.html for more info
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x210080;
    return 0;
}

// iOS 8 arm64
int get_PE_i_can_has_debugger_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 08 00 00 B9 02 00 00 14 1F 00 00 B9 1F 20 03 D5 1F 20 03 D5
    // str w8, [x0]
    // b 0xffffff80024162e4
    // str wzr, [x0]
    // nop
    // nop
    uint8_t search[] = { 0x08, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x14, 0x1F, 0x00, 0x00, 0xB9, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"PE_i_can_has_debugger\" patch\n",__FUNCTION__);
        printf("%s: Trying a more recent \"PE_i_can_has_debugger\" patch\n",__FUNCTION__);
        return get_PE_i_can_has_debugger_patch_ios9(kernel_buf,kernel_len);
    }
    printf("%s: Found \"PE_i_can_has_debugger\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    // loc starts at str w8, [x0], we can add +0x4 to go a line forward and -0x4 to go back
    printf("%s: Found \"PE_i_can_has_debugger\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x1F 0x20 0x03 0xD5 for near top of sandbox patch at cbz w8, ...
    // 0x20 0x00 0x80 0x52 for bottom of sandbox patch at ldr w0, data_ ...
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n", __FUNCTION__,(void*)(xref_stuff - 0x4 - 0x4 - 0x4 - 0x4));
    // 0xD503201F is nop for cbz
    *(uint32_t *) (kernel_buf + xref_stuff - 0x4 - 0x4 - 0x4 - 0x4) = 0xD503201F;
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n", __FUNCTION__,(void*)(xref_stuff + 0x4 + 0x4 + 0x4 + 0x4 + 0x4));
    // 0x0x52800020 is mov w0, 0x1 to make the func return 1 always
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4 + 0x4 + 0x4 + 0x4 + 0x4) = 0x52800020;
    return 0;
}

// iOS 9 arm64
int get_PE_i_can_has_debugger_patch_ios9(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 08 00 00 B9 02 00 00 14 1F 00 00 B9 1F 20 03 D5
    // str w8, [x0]
    // b 0xffffff80024162e4
    // str wzr, [x0]
    // nop
    uint8_t search[] = { 0x08, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x14, 0x1F, 0x00, 0x00, 0xB9, 0x1F, 0x20, 0x03, 0xD5 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"PE_i_can_has_debugger\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"PE_i_can_has_debugger\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    // loc starts at str w8, [x0], we can add +0x4 to go a line forward and -0x4 to go back
    printf("%s: Found \"PE_i_can_has_debugger\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x1F 0x20 0x03 0xD5 for near top of sandbox patch at cbz w8, ...
    // 0x20 0x00 0x80 0x52 for bottom of sandbox patch at ldr w0, data_ ...
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n", __FUNCTION__,(void*)(xref_stuff - 0x4 - 0x4 - 0x4 - 0x4));
    // 0xD503201F is nop for cbz
    *(uint32_t *) (kernel_buf + xref_stuff - 0x4 - 0x4 - 0x4 - 0x4) = 0xD503201F;
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n", __FUNCTION__,(void*)(xref_stuff + 0x4 + 0x4 + 0x4 + 0x4));
    // 0x0x52800020 is mov w0, 0x1 to make the func return 1 always
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4 + 0x4 + 0x4 + 0x4) = 0x52800020;
    return 0;
}

// iOS 8 arm64
int get_mapIO_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "_mapForIO";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"_mapForIO\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_mapForIO\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"_mapForIO\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_mapForIO\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t bne = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_b_conditional_64);
    if(!bne) {
        printf("%s: Could not find \"_mapForIO\" b.ne insn\n",__FUNCTION__);
        return -1;
    }
    addr_t b = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, bne, insn_is_b_unconditional_64);
    if(!b) {
        printf("%s: Could not find \"_mapForIO\" b insn\n",__FUNCTION__);
        return -1;
    }
    b = (addr_t)GET_OFFSET(kernel_len, b);
    printf("%s: Found \"_mapForIO\" patch loc at %p\n",__FUNCTION__,(void*)(b));
    printf("%s: Patching \"_mapForIO\" at %p\n", __FUNCTION__,(void*)(b));
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + b) = 0xD503201F;
    return 0;
}

// iOS 8 arm64
int get_vm_fault_enter_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search CD 06 00 35
    // tbnz w8, #0x15, 0xffffff8002079a8c
    // cbnz w13, 0xffffff8002079b3c
    // we need to make tbnz w8, #0x15, 0xffffff8002079a8c a mov w13, #0x1
    // because cbnz w13, 0xffffff8002079b3c is checking register w13
    uint8_t search[] = { 0xCD, 0x06, 0x00, 0x35 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff - 0x4; // move to tbnz w8, #0x15, 0xffffff8002079a8c
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002d; // mov w13, #0x1
    return 0;
}

// iOS 8.4 arm64
int get_vm_fault_enter_patch_ios84(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 4E 06 00 35 
    // tbnz w8, #0x15, 0xffffff800207e7bc
    // cbnz w14, 0xffffff800207e860
    // we need to make tbnz w8, #0x15, 0xffffff800207e7bc a mov w14, #0x1
    // because cbnz w14, 0xffffff800207e860 is checking register w14
    uint8_t search[] = { 0x4E, 0x06, 0x00, 0x35 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff - 0x4; // move to tbnz w8, #0x15, 0xffffff800207e7bc
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002e; // mov w14, #0x1
    return 0;
}

// iOS 9 arm64
int get_vm_fault_enter_patch_ios9(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 0A 01 0A 12 6A 00 00 34
    // and w10, w8, #0x400000
    // cbz w10, 0xffffff800409832c
    uint8_t search[] = { 0x0A, 0x01, 0x0A, 0x12, 0x6A, 0x00, 0x00, 0x34 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(ent_loc));
    addr_t b = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_b_unconditional_64);
    if(!b) {
        printf("%s: Could not find \"vm_fault_enter\" b insn\n",__FUNCTION__);
        return -1;
    }
    b = (addr_t)GET_OFFSET(kernel_len, b);
    b = b + 0x4; // move to ldr w10, [x29, #0x10]
    b = b + 0x4; // move to and w12, w20, #0x4
    b = b + 0x4; // move to str w10, [sp, #0x34]
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,(void*)(b));
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(b));
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + b) = 0x5280002a; // mov w10, 0x1
    return 0;
}

// iOS 10 arm64
int get_vm_fault_enter_patch_ios10(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search
    // 4019407a8a7a1d12
    // ccmp w10, #0, #0, ne
    // and w10, w20, #0xfffffffb
    // 
    // tst w8, #0x100000
    // ccmp w10, #0, #0x4, eq
    // and w10, w26, #0x4
    // ccmp w10, #0, #0, ne
    // and w10, w20, #0xfffffffb
    // stp w10, w12, [x29, #-0xc0]
    // csel w10, w10, w20, eq
    // 
    // should work on ios 10.2-10.3.3
    uint8_t search[] = { 0x40, 0x19, 0x40, 0x7A, 0x8A, 0x7A, 0x1D, 0x12 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x4; // move to and w10, w20, #0xfffffffb
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002c; // mov w12, 0x1
    xref_stuff = xref_stuff + 0x4; // move to stp w10, w12, [x29, #-0xc0]
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002a; // mov w10, 0x1
    return 0;
}

// iOS 11 arm64
int get_vm_fault_enter_patch_ios11(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search
    // ac1740b91f010e72
    // ldr w12, [x29, #0x14]
    // tst w8, #0x40000
    // 
    // ldr w12, [x29, #0x14]
    // tst w8, #0x40000
    // cset w10, eq
    // and w10, w10, w28, lsr #0x2
    // tst w24, #0x4
    // cset w11, eq
    // and w13, w28, #0xfffffffb -> mov w12, 0x1
    // tst w11, w10
    // str w13, [sp, #0x100] -> mov w10, 0x1
    // csel w10, w13, w28, ne
    // str w10, [sp, #0x11c]
    // stp x25, x20, [sp, #0x108]
    // str w12, [sp, #0x104]
    // cbz w12, 0xfffffff0071867c0
    // mov w28, #0
    // mov w27, #0
    // b 0xfffffff007186e74
    // tbnz w8, #0x13, 0xfffffff0071867e8
    // 
    // should work on ios 11.1-11.4.1
    uint8_t search[] = { 0xac, 0x17, 0x40, 0xb9, 0x1f, 0x01, 0x0e, 0x72 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x4; // move to tst w8, #0x40000
    xref_stuff = xref_stuff + 0x4; // move to cset w10, eq
    xref_stuff = xref_stuff + 0x4; // move to and w10, w10, w28, lsr #0x2
    xref_stuff = xref_stuff + 0x4; // move to tst w24, #0x4
    xref_stuff = xref_stuff + 0x4; // move to cset w11, eq
    xref_stuff = xref_stuff + 0x4; // move to and w13, w28, #0xfffffffb
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002c; // mov w12, 0x1
    xref_stuff = xref_stuff + 0x4; // move to tst w11, w10
    xref_stuff = xref_stuff + 0x4; // move to str w13, [sp, #0x100]
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002a; // mov w10, 0x1
    return 0;
}

// iOS 7 arm64
int get_vm_fault_enter_patch_ios7(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search A8 00 90 36 D5 00 08 37 17 00 80 52
    // tbnz w8, #0x13, 0xffffff80003305fc -> ldr w10, [sp, #0x30]
    // mov w23, #0
    // ldr w10, [sp, #0x30] -> tbnz w8, #0x13, 0xffffff80003305fc -> mov w10, 0x1
    // cbnz w10, 0xffffff8000330700
    // .. and heres our search pattern
    // tbz w8, #0x12, 0xffffff80003305f4
    // tbnz w21, #0x1, 0xffffff80003305fc
    // mov w23, #0
    // we need to move tbnz w8, #0x13, 0xffffff80003305fc around& make it a mov w10, 0x1
    // because cbnz w10, 0xffffff8000330700 is checking register w10
    uint8_t search[] = { 0xA8, 0x00, 0x90, 0x36, 0xD5, 0x00, 0x08, 0x37, 0x17, 0x00, 0x80, 0x52 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_fault_enter\" at %p\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff - 0x4; // move to cbnz w10, 0xffffff8000330700
    xref_stuff = xref_stuff - 0x4; // move to ldr w10, [sp, #0x30]
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002a; // mov w10, 0x1
    xref_stuff = xref_stuff - 0x4; // move to mov w23, #0
    xref_stuff = xref_stuff - 0x4; // move to tbnz w8, #0x13, 0xffffff80003305fc
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xb94033ea; // ldr w10, [sp, #0x30]
    return 0;
}

// iOS 8 arm64
int get_tfp0_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 00 01 40 B9 15 09 40 B9 13 09 40 F9
    // ldr w0, [x8]
    // ldr w21, [x8, #0x8]
    // ldr x19, [x8, #0x10]
    uint8_t search[] = { 0x00, 0x01, 0x40, 0xB9, 0x15, 0x09, 0x40, 0xB9, 0x13, 0x09, 0x40, 0xF9 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"tfp0\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"tfp0\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    printf("%s: Found \"tfp0\" xref at %p\n", __FUNCTION__,(void*)(ent_loc));
    addr_t bl = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_bl_64);
    if(!bl) {
        printf("%s: Could not find \"tfp0\" bl insn\n",__FUNCTION__);
        return -1;
    }
    bl = (addr_t)GET_OFFSET(kernel_len, bl);
    bl = bl - 0x4; // move to cbz w21, 0xffffff80043ca0d4
    printf("%s: Found \"tfp0\" patch loc at %p\n",__FUNCTION__,(void*)(bl));
    printf("%s: Patching \"tfp0\" at %p\n", __FUNCTION__,(void*)(bl));
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + bl) = 0xD503201F; // nop
    return 0;
}

// iOS 8 arm64
int get_sandbox_trace_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search E8 37 40 F9 1F 00 00 71
    // ldr x8, [sp, #0x68]
    // cmp w0, #0
    uint8_t search[] = { 0xE8, 0x37, 0x40, 0xF9, 0x1F, 0x00, 0x00, 0x71 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"sandbox_trace\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sandbox_trace\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    printf("%s: Found \"sandbox_trace\" xref at %p\n", __FUNCTION__,(void*)(ent_loc));
    addr_t cbz = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_cbz_64);
    if(!cbz) {
        printf("%s: Could not find \"sandbox_trace\" cbz insn\n",__FUNCTION__);
        return -1;
    }
    addr_t bl = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, cbz, insn_is_bl_64);
    if(!bl) {
        printf("%s: Could not find \"sandbox_trace\" bl insn\n",__FUNCTION__);
        return -1;
    }
    uint8_t* address = (uint8_t *)bl + insn_bl_imm32_64(bl); // funcbegin
    bl = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, (uint32_t *)address, insn_is_bl_64);
    if(!bl) {
        printf("%s: Could not find \"sandbox_trace\" bl insn\n",__FUNCTION__);
        return -1;
    }
    bl = (addr_t)GET_OFFSET(kernel_len, bl);
    printf("%s: Found \"sandbox_trace\" patch loc at %p\n",__FUNCTION__,(void*)(bl));
    printf("%s: Patching \"sandbox_trace\" at %p\n", __FUNCTION__,(void*)(bl));
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + bl) = 0xD503201F; // nop
    return 0;
}

addr_t get_sb_evaluate(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "bad filter type";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"rootless_entitlement\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"rootless_entitlement\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"rootless_entitlement\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    return beg_func;
}

addr_t get_sb_evaluate_10(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "bad string";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"rootless_entitlement\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"rootless_entitlement\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"rootless_entitlement\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    return beg_func;
}

int64_t get_vn_getpath(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // %s: vn_getpath returned 0x%x\n and find last bl
    char* str = "%s: vn_getpath returned 0x%x\n";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"vn_getpath\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vn_getpath\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"vn_getpath\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vn_getpath\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t bl = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_bl_64);
    if(!bl) {
        printf("%s: Could not find \"vn_getpath\" bl insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vn_getpath\" bl insn at %p\n", __FUNCTION__,(void*)(bl));
    addr_t br = (addr_t)find_br_address_with_bl_64(0, kernel_buf, kernel_len, bl); // br x16
    if(!br) {
        printf("%s: Could not find \"vn_getpath\" br insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vn_getpath\" br insn at %p\n", __FUNCTION__,(void*)(br));
    xref_stuff = br - 0x4; // move to ldr x16, [x16, #0x2b0]
    xref_stuff = xref_stuff - 0x4; // move to adrp x16, 0xffffff80026b0000
    return xref_stuff; // funcbegin sub_ffffff800268dcf0 ios 8.4 ip5
}

addr_t get_sb_evaluate_offset(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // rootless_entitlement
    // %s[%d] Container: %s (sandbox)\n
    char* str = "bad filter type";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"rootless_entitlement\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"sb_evaluate_offset\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sb_evaluate_offset\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"sb_evaluate_offset\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sb_evaluate_offset\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    return beg_func;
}

addr_t get_sb_evaluate_offset_10(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // rootless_entitlement
    // %s[%d] Container: %s (sandbox)\n
    char* str = "bad string";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"rootless_entitlement\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"rootless_entitlement\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"sb_evaluate_offset\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sb_evaluate_offset\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
       printf("%s: Could not find \"sb_evaluate_offset\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sb_evaluate_offset\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    return beg_func;
}

// iOS 9 arm64
int get_virtual_bool_AppleSEPManager_start_patch_ios9(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "_sep_panic_timer != NULL"; // virtual bool AppleSEPManager::start(IOService *)
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"virtual bool AppleSEPManager::start(IOService *)\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"virtual bool AppleSEPManager::start(IOService *)\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"virtual bool AppleSEPManager::start(IOService *)\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"virtual bool AppleSEPManager::start(IOService *)\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"virtual bool AppleSEPManager::start(IOService *)\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"virtual bool AppleSEPManager::start(IOService *)\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    beg_func = (addr_t)GET_OFFSET(kernel_len, beg_func); // offset that we use for patching the kernel
    printf("%s: Patching \"virtual bool AppleSEPManager::start(IOService *)\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    beg_func = beg_func + 0x4;
    printf("%s: Patching \"virtual bool AppleSEPManager::start(IOService *)\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0; // ret
    return 0;
}

// iOS 7 arm64
int get_sks_request_timeout_patch_ios7(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "\"sks request timeout\"";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"sks request timeout\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"sks request timeout\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"sks request timeout\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    beg_func = (addr_t)GET_OFFSET(kernel_len, beg_func); // offset that we use for patching the kernel
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    beg_func = beg_func + 0x4;
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0; // ret
    beg_func = beg_func + 0x4;
    return 0;
}

// iOS 8 arm64
int get_sandbox_patch_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // Extracted from Taig 8.4 jailbreak (thanks @in7egral)
    // it replaces the first instruction in the sandbox evaluate function in the kernel with a branch instruction that jumps to a function we create. this function we create should look at the path and force it to bypass sandbox by returning 0x1800000000 if it is outside of /private/var/mobile, or inside of /private/var/mobile/Library/Preferences but not /private/var/mobile/Library/Preferences/com.apple* but otherwise at the very end of our function it does two things, one it runs the first instruction from the sandbox evaluate function that was present from before we modified it earlier and then two it has another branch instruction but this time it branches back to the original sandbox evaluate function from apple but at funcbegin+1 aka the second line of the function, thereby skipping the branch instruction from earlier that allowed us to run our function. it notably has to also call the _vn_getpath function from our custom function, so in all it means we need a payload, _vn_getpath patchfinder, and a sb_eval patchfinder for any of this to work
    uint8_t payload[0x190] = {
        0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xF4, 0x4F, 0xBF, 0xA9, 0xF6, 0x57, 0xBF, 0xA9,
        0xFF, 0x43, 0x10, 0xD1, 0xF3, 0x03, 0x00, 0xAA, 0xF4, 0x03, 0x01, 0xAA, 0xF5, 0x03, 0x02, 0xAA,
        0xF6, 0x03, 0x03, 0xAA, 0xC0, 0x26, 0x40, 0xF9, 0x1F, 0x04, 0x00, 0xF1, 0x41, 0x04, 0x00, 0x54,
        0xC0, 0x2A, 0x40, 0xF9, 0x00, 0x04, 0x00, 0xB4, 0x1F, 0x20, 0x03, 0xD5, 0xE1, 0x03, 0x00, 0x91,
        0xE2, 0x03, 0x10, 0x91, 0x03, 0x80, 0x80, 0xD2, 0x43, 0x00, 0x00, 0xF9, 0x11, 0x11, 0x11, 0x11,
        0xE3, 0x03, 0x16, 0xAA, 0x00, 0x03, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x10,
        0x1E, 0x00, 0x00, 0x94, 0x80, 0x02, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x30,
        0x1A, 0x00, 0x00, 0x94, 0x20, 0x01, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x05, 0x00, 0x30,
        0x16, 0x00, 0x00, 0x94, 0x80, 0x01, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x06, 0x00, 0x70,
        0x12, 0x00, 0x00, 0x94, 0x00, 0x01, 0x00, 0xB5, 0x00, 0x03, 0x80, 0xD2, 0x00, 0x7C, 0x60, 0xD3,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xC0, 0x03, 0x5F, 0xD6, 0xE0, 0x03, 0x13, 0xAA, 0xE1, 0x03, 0x14, 0xAA, 0xE2, 0x03, 0x15, 0xAA,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0x04, 0x00, 0x40, 0x39, 0x25, 0x00, 0x40, 0x39,
        0x25, 0x01, 0x00, 0x34, 0x9F, 0x00, 0x05, 0x6B, 0xA1, 0x00, 0x00, 0x54, 0xC4, 0x00, 0x00, 0x34,
        0x00, 0x04, 0x00, 0x91, 0x21, 0x04, 0x00, 0x91, 0xF8, 0xFF, 0xFF, 0x17, 0x20, 0x00, 0x80, 0x52,
        0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x2F, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x74, 0x6D, 0x70, 0x00, 0x2F, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65,
        0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F,
        0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50, 0x72, 0x65,
        0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x2F, 0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70,
        0x6C, 0x65, 0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F,
        0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50,
        0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // int64_t sub_ffffff8002ccd160(void* arg1, int64_t* arg2, int32_t arg3, void* arg4)
    // stp x29, x30, [sp, #-0x10]!
    // mov x29, sp
    // stp x20, x19, [sp, #-0x10]!
    // stp x22, x21, [sp, #-0x10]!
    // sub sp, sp, #0x410
    // mov x19, x0
    // mov x20, x1
    // mov x21, x2
    // mov x22, x3
    // ldr x0, [x22, #0x48]
    // cmp x0, #0x1
    // b.ne 0xffffff8002ccd214
    // ldr x0, [x22, #0x50]
    // cbz x0, 0xffffff8002ccd214
    // nop
    // mov x1, sp
    // add x2, sp, #0x400
    // mov x3, #0x400
    // str x3, [x2]
    // bl 0xffffff800268dcf0 -> _vn_getpath
    // mov x3, x22
    // cbnz x0, 0xffffff8002ccd214
    // mov x0, sp
    // adr x1, 0xffffff8002ccd26c -> /private/var/tmp
    // bl 0xffffff8002ccd238 -> sub_ffffff8002ccd238
    // cbz x0, 0xffffff8002ccd214
    // mov x0, sp
    // adr x1, 0xffffff8002ccd27d -> /private/var/mobile
    // bl 0xffffff8002ccd238 -> sub_ffffff8002ccd238
    // cbnz x0, 0xffffff8002ccd1f8
    // mov x0, sp
    // adr x1, 0xffffff8002ccd291 -> /private/var/mobile/Library/Preferences/com.apple
    // bl 0xffffff8002ccd238 -> sub_ffffff8002ccd238
    // cbz x0, 0xffffff8002ccd214
    // mov x0, sp
    // adr x1, 0xffffff8002ccd2c3 -> /private/var/mobile/Library/Preferences
    // bl 0xffffff8002ccd238 -> sub_ffffff8002ccd238
    // cbnz x0, 0xffffff8002ccd214
    // mov x0, #0x18
    // lsl x0, x0, #0x20
    // add sp, sp, #0x410
    // ldp x22, x21, [sp], #0x10
    // ldp x20, x19, [sp], #0x10
    // ldp x29, x30, [sp], #0x10
    // ret -> return 0x1800000000
    // mov x0, x19
    // mov x1, x20
    // mov x2, x21
    // add sp, sp, #0x410
    // ldp x22, x21, [sp], #0x10
    // ldp x20, x19, [sp], #0x10
    // ldp x29, x30, [sp], #0x10
    // stp x28, x27, [sp, #-0x60]!
    // b 0xffffff8002cbfd60 -> sb_evaluate funcbegin insn+0x4
    // int64_t sub_ffffff8002ccd238(char* arg1, char* arg2)
    // ldrb w4, [x0]
    // ldrb w5, [x1]
    // cbz w5, 0xffffff8002ccd264
    // cmp w4, w5
    // b.ne 0xffffff8002ccd25c
    // cbz w4, 0xffffff8002ccd264
    // add x0, x0, #0x1
    // add x1, x1, #0x1
    // b 0xffffff8002ccd238
    // mov w0, #0x1
    // ret
    // mov w0, #0
    // ret
    uint32_t sb_evaluate = get_sb_evaluate(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t vn_getpath = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t sb_evaluate_offset = get_sb_evaluate_offset(kernel_buf, kernel_len); // xref& bof64
    uint32_t *payloadAsUint32 = (uint32_t *)payload;
    uint32_t patchValue;
    char* str = "\"sks request timeout\"";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"sks request timeout\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"sks request timeout\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"sks request timeout\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    beg_func = (addr_t)GET_OFFSET(kernel_len, beg_func); // offset that we use for patching the kernel
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    beg_func = beg_func + 0x4;
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0; // ret
    beg_func = beg_func + 0x4;
    uint64_t sb_evaluate_hook_offset = beg_func;
    beg_func = (addr_t)GET_OFFSET2(kernel_len, (uintptr_t)beg_func); // kernel offset which we need in order to create bl or b calls
    uint32_t sb_evaluate_hook = beg_func;
    uint64_t offset = beg_func;
    for ( uint32_t i = 0; i < 0x190; ++i )
    {
        uint32_t dataOffset = payloadAsUint32[i];
        if (dataOffset == 0xCCCCCCCC) { // second to last line of our payload function
            // ios 9.3.5 a9ba6ffc
            // ios 9.2 a9ba6ffc
            // ios 9.0 a9ba6ffc
            // ios 8.4 a9ba6ffc
            // ios 8.0 a9ba6ffc
            patchValue = 0xA9BA6FFC; // first insn in the sb_evaluate function from before we modified it
            // so basically here we are running the instruction from the sb_evaluate function that we removed from earlier
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0xDDDDDDDD) {
            // b unconditional call to the sb_evaluate function
            uint64_t origin = offset;
            uint64_t target = get_sb_evaluate(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            target = target + 0x4; // skip to next line
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0x11111111) {
            // bl call to the vn_getpath function
            uint64_t origin = offset;
            int64_t target = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x94000000; // 0x94000000 is bl
            payloadAsUint32[i] = patchValue;
        }
        offset += sizeof(uint32_t);
    }
    // insert payload starting at funcbegin insn for the sb_evaluate_hook function
    offset = sb_evaluate_hook_offset;
    uint32_t count = sizeof(payload) / sizeof(uint32_t);
    for(uint32_t i=0; i < count; ++i)
    {
        printf("%s: Patching \"sandbox\" at %p\n", __FUNCTION__,(void*)(offset));
        *(uint32_t *) (kernel_buf + offset) = payloadAsUint32[i];
        offset += sizeof(uint32_t);
    }
    // replace the first line in the sb_evaluate function with a b unconditional call to our payload
    uint32_t branch_instr = (sb_evaluate_hook - sb_evaluate) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
    *(uint32_t *) (kernel_buf + sb_evaluate_offset) = branch_instr;
    return 0;
}

// iOS 9 arm64
int get_sandbox_patch_ios9(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // Extracted from Taig 8.4 jailbreak (thanks @in7egral)
    // this is a modified taig sandbox payload that replaces the first instruction in the sandbox evaluate function in the kernel with a branch instruction that jumps to a function we create. this function we create should force it to bypass sandbox by returning 0x1800000000.
    uint8_t payload[0x190] = {
        0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xF4, 0x4F, 0xBF, 0xA9, 0xF6, 0x57, 0xBF, 0xA9,
        0xFF, 0x43, 0x10, 0xD1, 0xF3, 0x03, 0x00, 0xAA, 0xF4, 0x03, 0x01, 0xAA, 0xF5, 0x03, 0x02, 0xAA,
        0xF6, 0x03, 0x03, 0xAA, 0xC0, 0x26, 0x40, 0xF9, 0x00, 0x03, 0x80, 0xd2, 0x00, 0x7c, 0x60, 0xd3,
        0xff, 0x43, 0x10, 0x91, 0xf6, 0x57, 0xc1, 0xa8, 0xf4, 0x4f, 0xc1, 0xa8, 0xfd, 0x7b, 0xc1, 0xa8,
        0xc0, 0x03, 0x5f, 0xd6, 0xf4, 0x4f, 0xc1, 0xa8, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
        0xE3, 0x03, 0x16, 0xAA, 0x00, 0x03, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x10,
        0x1E, 0x00, 0x00, 0x94, 0x80, 0x02, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x30,
        0x1A, 0x00, 0x00, 0x94, 0x20, 0x01, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x05, 0x00, 0x30,
        0x16, 0x00, 0x00, 0x94, 0x80, 0x01, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x06, 0x00, 0x70,
        0x12, 0x00, 0x00, 0x94, 0x00, 0x01, 0x00, 0xB5, 0x00, 0x03, 0x80, 0xD2, 0x00, 0x7C, 0x60, 0xD3,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xC0, 0x03, 0x5F, 0xD6, 0xE0, 0x03, 0x13, 0xAA, 0xE1, 0x03, 0x14, 0xAA, 0xE2, 0x03, 0x15, 0xAA,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0x04, 0x00, 0x40, 0x39, 0x25, 0x00, 0x40, 0x39,
        0x25, 0x01, 0x00, 0x34, 0x9F, 0x00, 0x05, 0x6B, 0xA1, 0x00, 0x00, 0x54, 0xC4, 0x00, 0x00, 0x34,
        0x00, 0x04, 0x00, 0x91, 0x21, 0x04, 0x00, 0x91, 0xF8, 0xFF, 0xFF, 0x17, 0x20, 0x00, 0x80, 0x52,
        0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x2F, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x74, 0x6D, 0x70, 0x00, 0x2F, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65,
        0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F,
        0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50, 0x72, 0x65,
        0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x2F, 0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70,
        0x6C, 0x65, 0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F,
        0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50,
        0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // int64_t sub_ffffff80050f9b20(void* arg1, int64_t* arg2, int32_t arg3, void* arg4)
    // stp x29, x30, [sp, #-0x10]!
    // mov x29, sp
    // stp x20, x19, [sp, #-0x10]!
    // stp x22, x21, [sp, #-0x10]!
    // sub sp, sp, #0x410
    // mov x19, x0
    // mov x20, x1
    // mov x21, x2
    // mov x22, x3
    // ldr x0, [x22, #0x48]
    // mov x0, #0x18
    // lsl x0, x0, #0x20
    // add sp, sp, #0x410
    // ldp x22, x21, [sp], #0x10
    // ldp x20, x19, [sp], #0x10
    // ldp x29, x30, [sp], #0x10
    // ret -> return 0x1800000000
    // int64_t sub_ffffff8002ccd238(char* arg1, char* arg2)
    // ldrb w4, [x0]
    // ldrb w5, [x1]
    // cbz w5, 0xffffff8002ccd264
    // cmp w4, w5
    // b.ne 0xffffff8002ccd25c
    // cbz w4, 0xffffff8002ccd264
    // add x0, x0, #0x1
    // add x1, x1, #0x1
    // b 0xffffff8002ccd238
    // mov w0, #0x1
    // ret
    // mov w0, #0
    // ret
    uint32_t sb_evaluate = get_sb_evaluate(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t vn_getpath = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t sb_evaluate_offset = get_sb_evaluate_offset(kernel_buf, kernel_len); // xref& bof64
    uint32_t *payloadAsUint32 = (uint32_t *)payload;
    uint32_t patchValue;
    char* str = "\"sks request timeout\"";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"sks request timeout\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"sks request timeout\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"sks request timeout\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    beg_func = (addr_t)GET_OFFSET(kernel_len, beg_func); // offset that we use for patching the kernel
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    beg_func = beg_func + 0x4;
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0; // ret
    beg_func = beg_func + 0x4;
    uint64_t sb_evaluate_hook_offset = beg_func;
    beg_func = (addr_t)GET_OFFSET2(kernel_len, (uintptr_t)beg_func); // kernel offset which we need in order to create bl or b calls
    uint32_t sb_evaluate_hook = beg_func;
    uint64_t offset = beg_func;
    for ( uint32_t i = 0; i < 0x190; ++i )
    {
        uint32_t dataOffset = payloadAsUint32[i];
        if (dataOffset == 0xCCCCCCCC) { // second to last line of our payload function
            // ios 9.3.5 a9ba6ffc
            // ios 9.2 a9ba6ffc
            // ios 9.0 a9ba6ffc
            // ios 8.4 a9ba6ffc
            // ios 8.0 a9ba6ffc
            patchValue = 0xA9BA6FFC; // first insn in the sb_evaluate function from before we modified it
            // so basically here we are running the instruction from the sb_evaluate function that we removed from earlier
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0xDDDDDDDD) {
            // b unconditional call to the sb_evaluate function
            uint64_t origin = offset;
            uint64_t target = get_sb_evaluate(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            target = target + 0x4; // skip to next line
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0x11111111) {
            // bl call to the vn_getpath function
            uint64_t origin = offset;
            int64_t target = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x94000000; // 0x94000000 is bl
            payloadAsUint32[i] = patchValue;
        }
        offset += sizeof(uint32_t);
    }
    // insert payload starting at funcbegin insn for the sb_evaluate_hook function
    offset = sb_evaluate_hook_offset;
    uint32_t count = sizeof(payload) / sizeof(uint32_t);
    for(uint32_t i=0; i < count; ++i)
    {
        printf("%s: Patching \"sandbox\" at %p\n", __FUNCTION__,(void*)(offset));
        *(uint32_t *) (kernel_buf + offset) = payloadAsUint32[i];
        offset += sizeof(uint32_t);
    }
    // replace the first line in the sb_evaluate function with a b unconditional call to our payload
    uint32_t branch_instr = (sb_evaluate_hook - sb_evaluate) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
    *(uint32_t *) (kernel_buf + sb_evaluate_offset) = branch_instr;
    return 0;
}

// iOS 10 arm64
int get_sandbox_patch_ios10(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // Extracted from Taig 8.4 jailbreak (thanks @in7egral)
    // this is a modified taig sandbox payload that replaces the first instruction in the sandbox evaluate function in the kernel with a branch instruction that jumps to a function we create. this function we create should force it to bypass sandbox by returning 0x1800000000.
    uint8_t payload[0x190] = {
        0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xF4, 0x4F, 0xBF, 0xA9, 0xF6, 0x57, 0xBF, 0xA9,
        0xFF, 0x43, 0x10, 0xD1, 0xF3, 0x03, 0x00, 0xAA, 0xF4, 0x03, 0x01, 0xAA, 0xF5, 0x03, 0x02, 0xAA,
        0xF6, 0x03, 0x03, 0xAA, 0xC0, 0x26, 0x40, 0xF9, 0x00, 0x03, 0x80, 0xd2, 0x00, 0x7c, 0x60, 0xd3,
        0xff, 0x43, 0x10, 0x91, 0xf6, 0x57, 0xc1, 0xa8, 0xf4, 0x4f, 0xc1, 0xa8, 0xfd, 0x7b, 0xc1, 0xa8,
        0xc0, 0x03, 0x5f, 0xd6, 0xf4, 0x4f, 0xc1, 0xa8, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
        0xE3, 0x03, 0x16, 0xAA, 0x00, 0x03, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x10,
        0x1E, 0x00, 0x00, 0x94, 0x80, 0x02, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0x81, 0x05, 0x00, 0x30,
        0x1A, 0x00, 0x00, 0x94, 0x20, 0x01, 0x00, 0xB5, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x05, 0x00, 0x30,
        0x16, 0x00, 0x00, 0x94, 0x80, 0x01, 0x00, 0xB4, 0xE0, 0x03, 0x00, 0x91, 0xA1, 0x06, 0x00, 0x70,
        0x12, 0x00, 0x00, 0x94, 0x00, 0x01, 0x00, 0xB5, 0x00, 0x03, 0x80, 0xD2, 0x00, 0x7C, 0x60, 0xD3,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xC0, 0x03, 0x5F, 0xD6, 0xE0, 0x03, 0x13, 0xAA, 0xE1, 0x03, 0x14, 0xAA, 0xE2, 0x03, 0x15, 0xAA,
        0xFF, 0x43, 0x10, 0x91, 0xF6, 0x57, 0xC1, 0xA8, 0xF4, 0x4F, 0xC1, 0xA8, 0xFD, 0x7B, 0xC1, 0xA8,
        0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0x04, 0x00, 0x40, 0x39, 0x25, 0x00, 0x40, 0x39,
        0x25, 0x01, 0x00, 0x34, 0x9F, 0x00, 0x05, 0x6B, 0xA1, 0x00, 0x00, 0x54, 0xC4, 0x00, 0x00, 0x34,
        0x00, 0x04, 0x00, 0x91, 0x21, 0x04, 0x00, 0x91, 0xF8, 0xFF, 0xFF, 0x17, 0x20, 0x00, 0x80, 0x52,
        0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x2F, 0x70, 0x72, 0x69,
        0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x74, 0x6D, 0x70, 0x00, 0x2F, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65,
        0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x6D, 0x6F,
        0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50, 0x72, 0x65,
        0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x2F, 0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70,
        0x6C, 0x65, 0x00, 0x2F, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2F, 0x76, 0x61, 0x72, 0x2F,
        0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x2F, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2F, 0x50,
        0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // int64_t sub_ffffff80050f9b20(void* arg1, int64_t* arg2, int32_t arg3, void* arg4)
    // stp x29, x30, [sp, #-0x10]!
    // mov x29, sp
    // stp x20, x19, [sp, #-0x10]!
    // stp x22, x21, [sp, #-0x10]!
    // sub sp, sp, #0x410
    // mov x19, x0
    // mov x20, x1
    // mov x21, x2
    // mov x22, x3
    // ldr x0, [x22, #0x48]
    // mov x0, #0x18
    // lsl x0, x0, #0x20
    // add sp, sp, #0x410
    // ldp x22, x21, [sp], #0x10
    // ldp x20, x19, [sp], #0x10
    // ldp x29, x30, [sp], #0x10
    // ret -> return 0x1800000000
    // int64_t sub_ffffff8002ccd238(char* arg1, char* arg2)
    // ldrb w4, [x0]
    // ldrb w5, [x1]
    // cbz w5, 0xffffff8002ccd264
    // cmp w4, w5
    // b.ne 0xffffff8002ccd25c
    // cbz w4, 0xffffff8002ccd264
    // add x0, x0, #0x1
    // add x1, x1, #0x1
    // b 0xffffff8002ccd238
    // mov w0, #0x1
    // ret
    // mov w0, #0
    // ret
    uint32_t sb_evaluate = get_sb_evaluate_10(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t vn_getpath = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
    uint32_t sb_evaluate_offset = get_sb_evaluate_offset_10(kernel_buf, kernel_len); // xref& bof64
    uint32_t *payloadAsUint32 = (uint32_t *)payload;
    uint32_t patchValue;
    char* str = "AppleKeyStore: sks timeout strike %d\n";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str) - 1);
    if(!ent_loc) {
        printf("%s: Could not find \"sks request timeout\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = find_literal_ref_64(0, kernel_buf, kernel_len, (uint32_t*)kernel_buf, GET_OFFSET(kernel_len,ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"sks request timeout\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" xref at %p\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
        printf("%s: Could not find \"sks request timeout\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sks request timeout\" funcbegin insn at %p\n", __FUNCTION__,(void*)(beg_func));
    beg_func = (addr_t)GET_OFFSET(kernel_len, beg_func); // offset that we use for patching the kernel
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    beg_func = beg_func + 0x4;
    printf("%s: Patching \"sks request timeout\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0; // ret
    beg_func = beg_func + 0x4;
    uint64_t sb_evaluate_hook_offset = beg_func;
    beg_func = (addr_t)GET_OFFSET2(kernel_len, (uintptr_t)beg_func); // kernel offset which we need in order to create bl or b calls
    uint32_t sb_evaluate_hook = beg_func;
    uint64_t offset = beg_func;
    for ( uint32_t i = 0; i < 0x190; ++i )
    {
        uint32_t dataOffset = payloadAsUint32[i];
        if (dataOffset == 0xCCCCCCCC) { // second to last line of our payload function
            // ios 9.3.5 a9ba6ffc
            // ios 9.2 a9ba6ffc
            // ios 9.0 a9ba6ffc
            // ios 8.4 a9ba6ffc
            // ios 8.0 a9ba6ffc
            patchValue = 0xA9BA6FFC; // first insn in the sb_evaluate function from before we modified it
            // so basically here we are running the instruction from the sb_evaluate function that we removed from earlier
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0xDDDDDDDD) {
            // b unconditional call to the sb_evaluate function
            uint64_t origin = offset;
            uint64_t target = get_sb_evaluate_10(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            target = target + 0x4; // skip to next line
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
            payloadAsUint32[i] = patchValue;
        } else if (dataOffset == 0x11111111) {
            // bl call to the vn_getpath function
            uint64_t origin = offset;
            int64_t target = get_vn_getpath(kernel_buf, kernel_len); // find_literal_ref_64& find_last_insn_matching_64
            patchValue = ((int64_t)target - (int64_t)origin) >> 2 & 0x3FFFFFF | 0x94000000; // 0x94000000 is bl
            payloadAsUint32[i] = patchValue;
        }
        offset += sizeof(uint32_t);
    }
    // insert payload starting at funcbegin insn for the sb_evaluate_hook function
    offset = sb_evaluate_hook_offset;
    uint32_t count = sizeof(payload) / sizeof(uint32_t);
    for(uint32_t i=0; i < count; ++i)
    {
        printf("%s: Patching \"sandbox\" at %p\n", __FUNCTION__,(void*)(offset));
        *(uint32_t *) (kernel_buf + offset) = payloadAsUint32[i];
        offset += sizeof(uint32_t);
    }
    // replace the first line in the sb_evaluate function with a b unconditional call to our payload
    uint32_t branch_instr = (sb_evaluate_hook - sb_evaluate) >> 2 & 0x3FFFFFF | 0x14000000; // 0x14000000 is b
    *(uint32_t *) (kernel_buf + sb_evaluate_offset) = branch_instr;
    return 0;
}

// iOS 11 arm64
int get_amfi_out_of_my_way_patch_ios11(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    void* ent_loc = memmem(kernel_buf,kernel_len,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kernel_buf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    addr_t function = follow_call64(kernel_buf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kernel_buf + function) = 0x320003E0;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-m\t\tPatch mount_common (iOS 7, 8, 9, 10& 11 Only)\n");
        printf("\t-e\t\tPatch vm_map_enter (iOS 7, 8, 9, 10& 11 Only)\n");
        printf("\t-l\t\tPatch vm_map_protect (iOS 7, 8, 9, 10& 11 Only)\n");
        printf("\t-f\t\tPatch vm_fault_enter (iOS 7, 8, 9, 10& 11 Only)\n");
        printf("\t-s\t\tPatch PE_i_can_has_debugger (iOS 8& 9 Only)\n");
        printf("\t-a\t\tPatch map_IO (iOS 8, 9, 10& 11 Only)\n");
        printf("\t-t\t\tPatch tfp0 (iOS 8, 9& 10 Only)\n");
        printf("\t-p\t\tPatch sandbox_trace (iOS 8& 9 Only)\n");
        printf("\t-g\t\tPatch sandbox (iOS 8 Only)\n");
        printf("\t-j\t\tPatch sandbox (iOS 9 Only)\n");
        printf("\t-h\t\tPatch sandbox (iOS 10 Only)\n");
        printf("\t-v\t\tPatch virtual bool AppleSEPManager::start(IOService *) (iOS 9 Only)\n");
        printf("\t-k\t\tPatch sks request timeout (iOS 7 Only)\n");
        printf("\t-u\t\tPatch amfi_get_out_of_my_way (iOS 11, 12, 13& 14 Only)\n");
        printf("\t-n\t\tPatch NoMoreSIGABRT\n");
        printf("\t-o\t\tPatch undo NoMoreSIGABRT\n");
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    char *filename = argv[1];
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    init_kernel(0, filename);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-e") == 0) {
            printf("Kernel: Adding vm_map_enter patch...\n");
            get_vm_map_enter_patch_ios7(kernel_buf,kernel_len);
            get_vm_map_enter_patch_ios8(kernel_buf,kernel_len);
            get_vm_map_enter_patch_ios9(kernel_buf,kernel_len);
            get_vm_map_enter_patch_ios10(kernel_buf,kernel_len);
            get_vm_map_enter_patch_ios11(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-l") == 0) {
            printf("Kernel: Adding vm_map_protect patch...\n");
            get_vm_map_protect_patch_ios8(kernel_buf,kernel_len);
            get_vm_map_protect_patch_ios9(kernel_buf,kernel_len);
            get_vm_map_protect_patch_ios10(kernel_buf,kernel_len);
            get_vm_map_protect_patch_ios11(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-f") == 0) {
            printf("Kernel: Adding vm_fault_enter patch...\n");
            get_vm_fault_enter_patch_ios7(kernel_buf,kernel_len);
            get_vm_fault_enter_patch_ios8(kernel_buf,kernel_len);
            get_vm_fault_enter_patch_ios84(kernel_buf,kernel_len);
            get_vm_fault_enter_patch_ios9(kernel_buf,kernel_len);
            get_vm_fault_enter_patch_ios10(kernel_buf,kernel_len);
            get_vm_fault_enter_patch_ios11(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-m") == 0) {
            printf("Kernel: Adding mount_common patch...\n");
            get_mount_common_patch_ios7(kernel_buf,kernel_len);
            get_mount_common_patch_ios8(kernel_buf,kernel_len);
            get_mount_common_patch_ios9(kernel_buf,kernel_len);
            get_mount_common_patch_ios10(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-s") == 0) {
            printf("Kernel: Adding PE_i_can_has_debugger patch...\n");
            get_PE_i_can_has_debugger_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-n") == 0) {
            printf("Kernel: Adding NoMoreSIGABRT patch...\n");
            get_NoMoreSIGABRT_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-o") == 0) {
            printf("Kernel: Adding undo NoMoreSIGABRT patch...\n");
            get_undo_NoMoreSIGABRT_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-a") == 0) {
            printf("Kernel: Adding map_IO patch...\n");
            get_mapIO_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding tfp0 patch...\n");
            get_tfp0_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-p") == 0) {
            printf("Kernel: Adding sandbox_trace patch...\n");
            get_sandbox_trace_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-g") == 0) {
            printf("Kernel: Adding sandbox patch...\n");
            get_sandbox_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-j") == 0) {
            printf("Kernel: Adding sandbox patch...\n");
            get_sandbox_patch_ios9(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-h") == 0) {
            printf("Kernel: Adding sandbox patch...\n");
            get_sandbox_patch_ios10(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-v") == 0) {
            printf("Kernel: Adding virtual bool AppleSEPManager::start(IOService *) patch...\n");
            get_virtual_bool_AppleSEPManager_start_patch_ios9(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-k") == 0) {
            printf("Kernel: Adding sks request timeout patch...\n");
            get_sks_request_timeout_patch_ios7(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-u") == 0) {
            printf("Kernel: Adding amfi_get_out_of_my_way patch...\n");
            get_amfi_out_of_my_way_patch_ios11(kernel_buf,kernel_len);
        }
    }
    
    term_kernel();
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
