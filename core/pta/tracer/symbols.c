#include "tracer.h"
#include "symbols.h"

#ifdef LINUX_BUILD
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

void remove_spaces(char* s) {
    char* d = s;
    do {
        while (*d == ' ') {
            ++d;
        }
    } while (*s++ = *d++);
}

void init_host_mem_regions(tracer_t* tracer) {
    ssize_t read;
    size_t len;
    char * line = NULL;

    FILE *f = fopen("/proc/iomem", "r");

    if (f == NULL) {
        printf("Cannot get host memory regions...exiting\n");
        exit(-1);
    }

    tracer->mem_region_start_arr = malloc(sizeof(uintptr_t)*100);
    tracer->mem_region_end_arr = malloc(sizeof(uintptr_t)*100);
    if (tracer->mem_region_start_arr == NULL || tracer->mem_region_end_arr == NULL) {
        printf("Out of memory...exiting\n");
        exit(-1);
    }

    int idx = 0;

    while ((read = getline(&line, &len, f)) != -1) {
        char* addr = strtok(line, ":");                  
        char* devname = strtok(NULL, "");
        remove_spaces(devname);

        if (strcmp(devname, "SystemRAM\n") == 0) {
            char* x1 = strtok(addr, "-");
            char* x2 = strtok(NULL, "");

            long long start = strtoll(x1, NULL, 16);
            long long end = strtoll(x2, NULL, 16);

            tracer->mem_region_start_arr[idx] = (uintptr_t)start;
            tracer->mem_region_end_arr[idx] = (uintptr_t)end;
            idx++;
        }
    }

    fclose(f);
    if (line)
        free(line);

    tracer->mem_region_arr_size = idx;
}

#endif

status_t init_symbols(tracer_t* tracer) {
	// init symbols/addresses information.
    // TODO: hard coded for now for security reasons. Need to come up with compiler flags to make it easier when deploying.
    addr_t va_init_task = 0xffff800011cf3480;

	tracer->init_task = canonical_addr(va_init_task);	
	tracer->os_data.init_task_fixed = tracer->init_task;

	tracer->page_shift = 12;
	tracer->page_size = TRACER_4KB;
    tracer->arm64.tg0 = TRACER_4KB;
    tracer->arm64.tg1 = TRACER_4KB;
    tracer->arm64.t0sz = 16;
    tracer->arm64.t1sz = 16;

    tracer->os_data.pid_offset = 1096;
    tracer->os_data.mm_offset = 912;
    tracer->os_data.tasks_offset = 832;
    tracer->os_data.name_offset = 1544;
    tracer->os_data.pgd_offset = 64; 

    tracer->mm_data.mmap = 0; 
    tracer->mm_data.brk = 280; 
    tracer->mm_data.start_brk = 272; 
    tracer->mm_data.start_stack = 288; 
    tracer->mm_data.start_code = 240; 
    tracer->mm_data.end_code = 248; 
    tracer->mm_data.start_data = 256; 
    tracer->mm_data.end_data = 264; 
    tracer->mm_data.vdso = 0; 

    tracer->vm_area_data.vm_flags = 80; 
    tracer->vm_area_data.vm_start = 0;
    tracer->vm_area_data.vm_end = 8;
    tracer->vm_area_data.vm_file = 160;
    tracer->vm_area_data.vm_next = 16;
    
    tracer->path_data.dentry = 8;

    tracer->file_data.f_path = 16;
    
    tracer->dentry_data.d_name = 32;
    
    tracer->qstr_data.name = 8;
    tracer->qstr_data.len = 4;

    tracer->elf64_hdr_data.e_phoff = 32;
    tracer->elf64_hdr_data.e_phnum = 56;
    tracer->elf64_hdr_data.e_phentsize = 54;

    tracer->elf64_phdr_data.p_type = 0;
    tracer->elf64_phdr_data.p_offset = 8;
    tracer->elf64_phdr_data.p_vaddr = 16;
    
    tracer->elf64_sym_data.st_name = 0;
    tracer->elf64_sym_data.st_value = 8;
    
    tracer->elf64_rela_data.r_addend = 16;
    tracer->elf64_rela_data.r_info = 8;
    tracer->elf64_rela_data.r_offset = 0;

#ifdef LINUX_BUILD
    init_host_mem_regions(tracer);
#endif

	return TRACER_S;
}
