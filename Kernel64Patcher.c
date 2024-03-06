/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

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
    printf("%s: Found \"vm_map_enter\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    // mov w9, w8 is 0xE9 0x03 0x08 0x2A which translates to 2a0803e9 in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x2A0803E9;
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
    printf("%s: Found \"vm_map_enter\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_enter\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_enter patch needs to be mov w9, w8 not a nop
    // mov w10, w8 is 0xEA 0x03 0x08 0x2A which translates to 2a0803ea in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0x2A0803EA;
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
    printf("%s: Found \"vm_map_protect\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_map_protect\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // however this vm_map_protect patch needs to be mov w11, w22 not a nop
    // mov w11, w22 is 0xEB 0x03 0x16 0x2A which translates to 2a1603eb in little endian
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4 + 0x4) = 0x2A1603EB;
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
    printf("%s: Found \"mount_common\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
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
    printf("%s: Found \"mount_common\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mount_common\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // add 0x8 to address https://github.com/TheRealClarity/wtfis/blob/main/wtfis/patchfinder64.c#L2121
    xref_stuff = xref_stuff + 0x8;
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
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
    printf("%s: Found \"NoMoreSIGABRT\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"NoMoreSIGABRT\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
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
    printf("%s: Found \"undo_NoMoreSIGABRT\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"undo_NoMoreSIGABRT\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
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
    printf("%s: Found \"PE_i_can_has_debugger\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x1F 0x20 0x03 0xD5 for near top of sandbox patch at cbz w8, ...
    // 0x20 0x00 0x80 0x52 for bottom of sandbox patch at ldr w0, data_ ...
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff - 0x4 - 0x4 - 0x4 - 0x4));
    // 0xD503201F is nop for cbz
    *(uint32_t *) (kernel_buf + xref_stuff - 0x4 - 0x4 - 0x4 - 0x4) = 0xD503201F;
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4 + 0x4 + 0x4 + 0x4 + 0x4));
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
    printf("%s: Found \"PE_i_can_has_debugger\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0x1F 0x20 0x03 0xD5 for near top of sandbox patch at cbz w8, ...
    // 0x20 0x00 0x80 0x52 for bottom of sandbox patch at ldr w0, data_ ...
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff - 0x4 - 0x4 - 0x4 - 0x4));
    // 0xD503201F is nop for cbz
    *(uint32_t *) (kernel_buf + xref_stuff - 0x4 - 0x4 - 0x4 - 0x4) = 0xD503201F;
    printf("%s: Patching \"PE_i_can_has_debugger\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4 + 0x4 + 0x4 + 0x4));
    // 0x0x52800020 is mov w0, 0x1 to make the func return 1 always
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4 + 0x4 + 0x4 + 0x4) = 0x52800020;
    return 0;
}

uint32_t* find_next_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction < (uintptr_t)kdata + ksize - 4) {
        current_instruction++;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

__unused static int insn_is_b_unconditional_64(uint32_t* i)
{
    if ((*i & 0xfc000000) == 0x14000000)
        return 1;
    else
        return 0;
}

// iOS 8 arm64
int get_mapIO_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 00 00 BC 52 40 58 80 72 00 08 00 11
    //MOV             W0, #0xE0000000
    //MOVK            W0, #0x2C2
    //ADD             W0, W0, #2
    uint8_t search[] = { 0x00, 0x00, 0xBC, 0x52, 0x40, 0x58, 0x80, 0x72, 0x00, 0x08, 0x00, 0x11 };

    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"mapIO_patch\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"mapIO_patch\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)find_next_insn_matching_64(0, kernel_buf, kernel_len, ent_loc, insn_is_b_unconditional_64);
    if(!xref_stuff) {
        printf("%s: Could not find \"mapIO_patch\" xref\n",__FUNCTION__);
        return -1;
    }
    xref_stuff = (addr_t)GET_OFFSET(kernel_len, xref_stuff);
    printf("%s: Found \"mapIO_patch\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"mapIO_patch\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

// iOS 8 arm64
int get_vm_fault_enter_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 1F 12 6A 00 00 34 5A 06 80 52
    // 8a 03 1f 12 6a 00 00 34 5a 06 80 52 0a 02 00 14 68 01 a8 37 cd 06 00 35
    // and w10, w28, #0x2
    // cbz w10, 0xffffff8002079a60
    // mov w26, #0x32
    // b 0xffffff800207a284
    // tbnz w8, #0x15, 0xffffff8002079a8c
    // cbnz w13, 0xffffff8002079b3c
    // take note that we are searching by 1f 12 and not 8a 03 1f 12 at the start
    // this means to get to the next line we need to add 0x2 not 0x4
    // we need to make tbnz w8, #0x15, 0xffffff8002079a8c a mov w13, #0x1
    // because cbnz w13, 0xffffff8002079b3c is checking register w13
    uint8_t search[] = { 0x1F, 0x12, 0x6A, 0x00, 0x00, 0x34, 0x5A, 0x06, 0x80, 0x52 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"vm_fault_enter\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"vm_fault_enter\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"vm_fault_enter\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"vm_fault_enter\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x2; // move to cbz w10, 0xffffff8002079a60
    xref_stuff = xref_stuff + 0x4; // move to mov w26, #0x32
    xref_stuff = xref_stuff + 0x4; // move to b 0xffffff800207a284
    xref_stuff = xref_stuff + 0x4; // move to tbnz w8, #0x15, 0xffffff8002079a8c
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x5280002d; // mov w13, #0x1
    return 0;
}

// iOS 8 arm64
int get_tfp0_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 13 09 40 F9 FF 17 00 F9 FF 27 00 B9 F5 0D 00 34
    // ldr x19, [x8, #0x10]
    // str xzr, [sp, #0x28]
    // str wzr, [sp, #0x24]
    // cbz w21, 0xffffff800237e46c
    uint8_t search[] = { 0x13, 0x09, 0x40, 0xF9, 0xFF, 0x17, 0x00, 0xF9, 0xFF, 0x27, 0x00, 0xB9, 0xF5, 0x0D, 0x00, 0x34 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"tfp0\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"tfp0\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"tfp0\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"tfp0\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // we want to make the cbz a nop, and the ent_loc starts at ldr x19, [x8, #0x10]
    // so we have to add 0x4, 3 times, in order to get to the cbz
    xref_stuff = xref_stuff + 0x4;
    xref_stuff = xref_stuff + 0x4;
    xref_stuff = xref_stuff + 0x4;
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

// iOS 8 arm64
int get_sandbox_trace_patch_ios8(void* kernel_buf,size_t kernel_len) {
    // search 02 10 1F 20 03 D5 08 01 40 39 1F 01 1C 72 E0 17 9F 1A 02 00 00 14 00 00 80 52 FD 7B C1 A8 C0 03 5F D6
    // e8e202101f2003d5080140391f011c72e0179f1a0200001400008052fd7bc1a8c0035fd6
    // ... heres two notable lines of code
    // bl 0xffffff8002c77d94
    // cbz w0, 0xffffff8002c7677c
    // ... and now for what we are actually searching for with memmem
    // adr x8, 0xffffff8002c7c3c0
    // nop
    // ldrb w8, [x8]
    // tst w8, #0x10
    // cset w0, eq
    // b 0xffffff8002c76780
    // mov w0, #0
    // ldp x29, x30, [sp], #0x10
    // ret
    // take note that we are searching by 02 10 and not E8 E2 02 10 at the start
    // this means to get to the next line we need to add 0x2 not 0x4
    // we need to make bl 0xffffff8002c77d94 a nop
    // this makes the function return 0 instead of 1
    uint8_t search[] = { 0x02, 0x10, 0x1F, 0x20, 0x03, 0xD5, 0x08, 0x01, 0x40, 0x39, 0x1F, 0x01, 0x1C, 0x72, 0xE0, 0x17, 0x9F, 0x1A, 0x02, 0x00, 0x00, 0x14, 0x00, 0x00, 0x80, 0x52, 0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"sandbox_trace\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sandbox_trace\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"sandbox_trace\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"sandbox_trace\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop also known as 1f2003D5 or 0x1F 0x20 0x03 0xD5
    // we want to make the bl a nop, and the ent_loc starts at adr x8, 0xffffff8002c7c3c0
    // so we have to add 0x2 to get to the nop on the next line down, then subtract 0x4 3 times to go 3 lines back
    xref_stuff = xref_stuff + 0x2;
    xref_stuff = xref_stuff - 0x4;
    xref_stuff = xref_stuff - 0x4;
    xref_stuff = xref_stuff - 0x4;
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

uint32_t* find_last_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        current_instruction--;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

__unused int insn_is_funcbegin_64(uint32_t* i)
{
    if (*i == 0xa9bf7bfd)
        return 1;
    if (*i == 0xa9bc5ff8)
        return 1;
    if (*i == 0xa9bd57f6)
        return 1;
    if (*i == 0xa9ba6ffc)
        return 1;
    if (*i == 0xa9bb67fa)
        return 1;
    if (*i == 0xa9be4ff4)
        return 1;
    return 0;
}

// iOS 8 arm64
int get_set_brick_state_patch_mobactivationd_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search "_set_brick_state" str
    // ... and heres some notable lines of code before that
    // bl 0x10000f298
    // cbnz w0, 0x10000c80c
    // take note that we are searching by 00 94 and not A2 02 00 94 at the start
    // this means to get to the next line we need to add 0x2 not 0x4
    // we need to make bl 0x10000f298 a mov w0, 0x1
    // because cbnz w0, 0x10000c80c is checking register w0
    char* str = "_set_brick_state";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"_set_brick_state\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_set_brick_state\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"_set_brick_state\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_set_brick_state\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"_set_brick_state\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // but this patch requires bl 0x10000caa4 to be mov w0, 0x1 which is 0x20 0x00 0x80 0x52 or 0x52800020 in little endian
    xref_stuff = xref_stuff - 0x4; // go one line back from "_set_brick_state" str xref
    xref_stuff = xref_stuff - 0x4; // go one line back from "_set_brick_state" str xref
    xref_stuff = xref_stuff - 0x4; // go one line back from "_set_brick_state" str xref
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020; // mov w0, 0x1
    return 0;
}

// iOS 8 arm64
int get_dealwith_activation_patch_mobactivationd_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search E1 63 00 91 E2 53 00 91 E0 03 13 AA
    // add x1, sp, #0x18
    // add x2, sp, #0x14
    // mov x0, x19
    // ... and heres two notable lines of code after that
    // bl 0x10000caa4
    // cbz w0, 0x10000c968
    uint8_t search[] = { 0xE1, 0x63, 0x00, 0x91, 0xE2, 0x53, 0x00, 0x91, 0xE0, 0x03, 0x13, 0xAA };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"dealwith_activation\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"dealwith_activation\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"dealwith_activation\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"dealwith_activation\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result, which can be used after the = sign to make this a nop
    // but this patch requires bl 0x10000caa4 to be mov w0, 0x1 which is 0x20 0x00 0x80 0x52 or 0x52800020 in little endian
    xref_stuff = xref_stuff + 0x4;
    xref_stuff = xref_stuff + 0x4;
    xref_stuff = xref_stuff + 0x4;
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020;
    return 0;
}

// iOS 8 arm64
int get_handle_deactivate_patch_mobactivationd_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "handle_deactivate";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"handle_deactivate\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"handle_deactivate\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"handle_deactivate\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
       printf("%s: Could not find \"handle_deactivate\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"handle_deactivate\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

// iOS 8 arm64
int get_check_build_expired_patch_mobactivationd_ios8(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* str = "check_build_expired";
    void* ent_loc = memmem(kernel_buf, kernel_len, str, sizeof(str));
    if(!ent_loc) {
        printf("%s: Could not find \"check_build_expired\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
       printf("%s: Could not find \"check_build_expired\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"check_build_expired\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    addr_t beg_func = (addr_t)find_last_insn_matching_64(0, kernel_buf, kernel_len, xref_stuff, insn_is_funcbegin_64);
    if(!beg_func) {
       printf("%s: Could not find \"check_build_expired\" funcbegin insn\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching \"check_build_expired\" at %p\n\n", __FUNCTION__,(void*)(beg_func));
    // 0xD503201F is nop
    // https://cryptii.com/pipes/integer-encoder
    // if you convert 1f2003D5 to a 32 bit unsigned integer in little endian https://archive.is/22JSe
    // you will get d503201f as a result
    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000; // mov w0, 0x0
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0; // ret
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-m\t\tPatch mount_common (iOS 7& 8 Only)\n");
        printf("\t-e\t\tPatch vm_map_enter (iOS 7& 8 Only)\n");
        printf("\t-l\t\tPatch vm_map_protect (iOS 8 Only)\n");
        printf("\t-f\t\tPatch vm_fault_enter (iOS 8 Only)\n");
        printf("\t-s\t\tPatch PE_i_can_has_debugger (iOS 8& 9 Only)\n");
        printf("\t-a\t\tPatch map_IO (iOS 8 Only)\n");
        printf("\t-t\t\tPatch tfp0 (iOS 8 Only)\n");
        printf("\t-p\t\tPatch sandbox_trace (iOS 8 Only)\n");
        printf("\t-g\t\tPatch _set_brick_state (iOS 8 Only)\n");
        printf("\t-b\t\tPatch dealwith_activation (iOS 8 Only)\n");
        printf("\t-c\t\tPatch handle_deactivate (iOS 8 Only)\n");
        printf("\t-d\t\tPatch check_build_expired (iOS 8 Only)\n");
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
        }
        if(strcmp(argv[i], "-l") == 0) {
            printf("Kernel: Adding vm_map_protect patch...\n");
            get_vm_map_protect_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-f") == 0) {
            printf("Kernel: Adding vm_fault_enter patch...\n");
            get_vm_fault_enter_patch_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-m") == 0) {
            printf("Kernel: Adding mount_common patch...\n");
            get_mount_common_patch_ios7(kernel_buf,kernel_len);
            get_mount_common_patch_ios8(kernel_buf,kernel_len);
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
            printf("Kernel: Adding _set_brick_state patch...\n");
            get_set_brick_state_patch_mobactivationd_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-b") == 0) {
            printf("Kernel: Adding dealwith_activation patch...\n");
            get_dealwith_activation_patch_mobactivationd_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-c") == 0) {
            printf("Kernel: Adding handle_deactivate patch...\n");
            get_handle_deactivate_patch_mobactivationd_ios8(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-d") == 0) {
            printf("Kernel: Adding check_build_expired patch...\n");
            get_check_build_expired_patch_mobactivationd_ios8(kernel_buf,kernel_len);
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
