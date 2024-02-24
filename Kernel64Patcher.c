/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

// iOS 7 vm_map_protect Patch
int get_vm_map_protect_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* vMMapProtectString = "!current->use_pmap";
    void* ent_loc = memmem(kernel_buf, kernel_len, vMMapProtectString, sizeof(vMMapProtectString));
    if(!ent_loc) {
        printf("%s: Could not find \"!current->use_pmap\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"!current->use_pmap\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"!current->use_pmap\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"!current->use_pmap\n",__FUNCTION__,(void*)xref_stuff);

    xref_stuff = xref_stuff + 0x4; // step one line forward in arm64 assembly
    
    // step 10 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    
    // step 10 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    
    // step 10 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    
    // step 10 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    
    // step 10 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    
    // step 5 lines backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly
    xref_stuff = xref_stuff - 0x4; // step one line backward in arm64 assembly

    printf("%s: Patching \"vm_map_protect\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop, so we are eliminating the clearing of VM_PROT_EXECUTE https://theapplewiki.com/wiki/Vm_map_protect_Patch
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    
    return 0;
}

// iOS 7 vm_map_enter Patch
int get_vm_map_enter_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char* vMMapEnterString = "EMBEDDED: %%s curprot cannot be write+execute. turning off execute\n";
    void* ent_loc = memmem(kernel_buf, kernel_len, vMMapEnterString, sizeof(vMMapEnterString));
    if(!ent_loc) {
        printf("%s: Could not find \"EMBEDDED: %%s curprot cannot be write+execute. turning off execute\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"EMBEDDED: %%s curprot cannot be write+execute. turning off execute\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"EMBEDDED: %%s curprot cannot be write+execute. turning off execute\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"EMBEDDED: %%s curprot cannot be write+execute. turning off execute\n",__FUNCTION__,(void*)xref_stuff);

    xref_stuff = xref_stuff + 0x4; // step one line forward in arm64 assembly
    
    xref_stuff = xref_stuff - 0x4 - 0x4 - 0x4 - 0x4 - 0x4 - 0x4 - 0x4 - 0x4; // step 8 lines backward in arm64 assembly

    printf("%s: Patching \"vm_map_enter\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // 0xD503201F is nop, so we are eliminating the conditional check https://theapplewiki.com/wiki/Vm_map_enter_Patch
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    
    return 0;
}

int get_mount_common_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    // search 29 03 10 32 F5 03 00 32 39 01 88 1A
    // ORR             w9, w25, #0x10000
    // ORR             w21, wzr, #0x1
    // CSEL            w25, w9, w8, eq
    // add 0x8 to address
    uint8_t search[] = { 0x29, 0x03, 0x10, 0x32, 0xF5, 0x03, 0x00, 0x32, 0x39, 0x01, 0x88, 0x1A };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"sub_ffffff8000385d68\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sub_ffffff8000385d68\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"sub_ffffff8000385d68\" patch xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"sub_ffffff8000385d68\n",__FUNCTION__,(void*)xref_stuff);
    printf("%s: Patching \"sub_ffffff8000385d68\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    // add 0x8 to address https://github.com/TheRealClarity/wtfis/blob/main/wtfis/patchfinder64.c#L2121
    xref_stuff = xref_stuff + 0x8;
    // 0xD503201F is nop
    *(uint32_t *) (kernel_buf + xref_stuff) = 0xD503201F;
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-a\t\tPatch vm_map_enter (iOS 7 Only)\n");
        printf("\t-s\t\tPatch vm_map_protect (iOS 7 Only)\n");
        printf("\t-s\t\tPatch mount_common (iOS 7 Only)\n");
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
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
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-e") == 0) {
            printf("Kernel: Adding vm_map_enter patch...\n");
            get_vm_map_enter_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-p") == 0) {
            printf("Kernel: Adding vm_map_protect patch...\n");
            get_vm_map_protect_patch(kernel_buf,kernel_len);
        }
        if(strcmp(argv[i], "-m") == 0) {
            printf("Kernel: Adding mount_common patch...\n");
            get_mount_common_patch(kernel_buf,kernel_len);
        }
    }
    
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
