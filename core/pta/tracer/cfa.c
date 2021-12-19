#include "tracer.h"
#include "uthash.h"
#include "jWrite.h"

#define ELF_HEADER 0x464c457f
#define PAGE_SHIFT 12

status_t find_symbol(tracer_t* tracer, addr_t vma_start, addr_t vma_end, char* path, addr_t process_gpd, addr_t pc) {
    char symbol_name[100];

    access_context_t ctx = { .pt = process_gpd, .addr = vma_start, .pt_lookup = true };

    // CHECK ELF HEADERS
    //
    uint32_t elf_header;
    addr_t text_segment_address = 0;
    if(TRACER_F == tracer_read_32bit(tracer, &ctx, &elf_header)) {
        return TRACER_F;
    }
        
    if (elf_header != ELF_HEADER) {
        return TRACER_F;
    } else {
        text_segment_address = vma_start;
    }
    
    if (text_segment_address == 0) {
        return TRACER_F;
    }

    // GET ELF INFOS
    //
    addr_t program_header_offset;
    ctx.addr = text_segment_address + tracer->elf64_hdr_data.e_phoff;
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &program_header_offset)) {    
        return TRACER_F;
    }

    uint16_t num_of_program_headers;
    ctx.addr = text_segment_address + tracer->elf64_hdr_data.e_phnum;
    if(TRACER_F == tracer_read_16bit(tracer, &ctx, &num_of_program_headers)) {        
        return TRACER_F;
    }

    uint16_t size_of_program_headers;
    ctx.addr = text_segment_address + tracer->elf64_hdr_data.e_phentsize;
    if(TRACER_F == tracer_read_16bit(tracer, &ctx, &size_of_program_headers)) {            
        return TRACER_F;
    }

    // Extracting DYNAMIC SEGMENT offset program headers
    //
    int counter = 0;
    uint32_t ph_type;
    addr_t dynamic_section_offset = 0, offset = 0, ph_vaddr;
    while (counter < num_of_program_headers)
    {
        ctx.addr = text_segment_address + offset + program_header_offset + tracer->elf64_phdr_data.p_type;
        if(TRACER_F == tracer_read_32bit(tracer, &ctx, &ph_type)) {
            return TRACER_F;
        }

        ctx.addr = text_segment_address + offset + program_header_offset + tracer->elf64_phdr_data.p_vaddr;
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &ph_vaddr)) {    
            return TRACER_F;
        }

        if (ph_type == 2) {
            dynamic_section_offset = ph_vaddr;
            break;
        }
        
        offset += size_of_program_headers;
        counter++;
    }

    // Exracting address of dynsym and dynstr sections from Dynamic section table entries
    addr_t dynsym_offset = 0, dynstr_offset = 0;
    addr_t dynsym_entry_size = 0x18, dynstr_size = 0;
    // addr_t rela_section_offset =0, rela_section_size=0, rela_section_entry=0x18; // set defaults incase not defined
    ctx.addr = text_segment_address + dynamic_section_offset;

    addr_t word, ptr;
    do
    {
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &word)) {    
            return TRACER_F;
        }
        ctx.addr += 0x8;

        if (TRACER_F == tracer_read_addr(tracer, &ctx, &ptr)) {    
            return TRACER_F;
        }

        ctx.addr += 0x8;

        if (word == 0x5) // .strtab section offset
            dynstr_offset = ptr;
        if (word == 0x6) // .symtab section offset
            dynsym_offset = ptr;

        if (word == 0xa) // size of .strtab section
            dynstr_size = ptr;
        if (word == 0xb) // size of an entry in .symtab section
            dynsym_entry_size = ptr;
    } while (word != 0x0 && ptr != 0x0);

    addr_t value;
    offset = dynsym_offset;        

    addr_t addr = pc;
    addr_t nearest = 0;
    addr_t nearest_offset = 0;

    while (true)
    {
        ctx.addr =  offset + tracer->elf64_sym_data.st_value;
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &value)) {    
            break;
        }

        addr_t value_addr = text_segment_address + value;

        if (addr >= value_addr)
        {
            if (nearest == 0)
            {
                nearest = value_addr;
                nearest_offset = offset;
                // function_name = key_str;
            }
            else if (addr - value_addr <= addr - nearest)
            {
                nearest = value_addr;
                nearest_offset = offset;
                // function_name = key_str;
            }
        }

        offset += dynsym_entry_size;
    }


    // if (text_segment_address + value < pc) {
    //     offset += dynsym_entry_size;
    //     continue;
    // }

    if (!nearest) {
        return TRACER_F;
    }

    uint32_t key;
    ctx.addr =  nearest_offset + tracer->elf64_sym_data.st_name;
    if(TRACER_F == tracer_read_32bit(tracer, &ctx, &key)) {
        return TRACER_F;
    }

    memset(symbol_name, 0, 100);
    ctx.addr = dynstr_offset + key;
    size_t bytes_read;

    if (TRACER_F == tracer_read(tracer, &ctx, 100, symbol_name, &bytes_read)) {
        return TRACER_F;
    }

    addr_t function_offset = addr - nearest;
    // DMSG("PC: 0x%lx     %s!%s+0x%lx\n", addr, path, symbol_name, function_offset);
    char symbol_with_offset[100];
    snprintf(symbol_with_offset, 100, "%s+0x%lx", symbol_name, function_offset);
    jwArr_object();
    jwObj_string(symbol_with_offset, path);
    jwEnd();

    return TRACER_S;
}

status_t analyze_mm(tracer_t* tracer, addr_t process, int pid, addr_t memory_map, addr_t pc, addr_t process_gpd) {
    addr_t vm_file_addr = 0;
    addr_t vm_area_struct_addr = 0;
    addr_t dentry_path = 0;
    uint32_t dname_len;
    char path[256];

    access_context_t ctx = { .pt = tracer->kpgd, .addr = memory_map + tracer->mm_data.mmap, .pt_lookup = true };
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &vm_area_struct_addr)) {
        return TRACER_F;
    }

    while(1) {
        addr_t vma_start;
        addr_t vma_end;
        addr_t vma_flags;
        size_t bytes_read;
        memset(path, 0, 256);

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_start;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_start)){
            return TRACER_F;
        }  
        
        if (pc < vma_start) {
            goto next; // not in this region
        }

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_end;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_end)){
            return TRACER_F;
        }

        if (pc > vma_end) {
            goto next; // not in this region
        }  

        // Found the correct VMA - find it's library/binary name
        //
        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_file;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_file_addr)){
            goto next;
        }  

        ctx.addr = vm_file_addr + tracer->file_data.f_path + tracer->path_data.dentry;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &dentry_path)){
            goto next;
        }

        ctx.addr = dentry_path + tracer->dentry_data.d_name + tracer->qstr_data.len;
        if(TRACER_F == tracer_read_32bit(tracer, &ctx, &dname_len)) {
            goto next;
        }

        ctx.addr = dentry_path + tracer->dentry_data.d_name + tracer->qstr_data.name + 16;
        if(TRACER_F == tracer_read(tracer, &ctx, dname_len, path, &bytes_read) || bytes_read != dname_len) {
            goto next;
        }

        path[dname_len+1] = '\0';

        if (TRACER_F == find_symbol(tracer, vma_start, vma_end, path, process_gpd, pc)) {
            goto next;
        }

next:
        /* follow the next pointer */
        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_next;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_area_struct_addr)) {
            return TRACER_F;
        }

        // Traversal completed, exit the loop
        //
        if(vm_area_struct_addr == 0) {
            return TRACER_S; 
        }  
    }       

    return TRACER_S;
}

status_t do_cfa(tracer_t* tracer, uint64_t* stack_frames, int num_stack_frames, addr_t process, int pid, char* buffer, unsigned int buflen) {
    // get memory map for the process
    //
    addr_t process_gpd;
    addr_t memory_map;

    access_context_t ctx = { .pt = tracer->kpgd, .addr = process + tracer->os_data.mm_offset, .pt_lookup = true };
    status_t result = tracer_read_addr(tracer, &ctx, &memory_map);        
    if(result == TRACER_F || memory_map == 0){
        DMSG("cannot retrieve memory map for process %d\n", pid);
        return TRACER_F;
    }

    if (TRACER_F == get_gpd(tracer, process, &process_gpd)) {
        return TRACER_F;
    }

    jwOpen(buffer, buflen, JW_ARRAY, JW_PRETTY);

    // Iterate over stack frames, find the respected symbols and libraries
    //
    for (int i=0;i<num_stack_frames;i++) {
        uint64_t pc = stack_frames[i];

        result = analyze_mm(tracer, process, pid, memory_map, pc, process_gpd);
        if (result != TRACER_S){
            jwClose();
            return result;
        }
    }    

    if (jwClose() != JWRITE_OK) {
        return TRACER_F;
    }

    return TRACER_S;
}

status_t cfa(tracer_t* tracer, int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen) {
    // Find process address
    //
    pid_t pid = 0;
    addr_t current_process = 0;
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    list_head = tracer->os_data.init_task_fixed + tracer->os_data.tasks_offset;
    cur_list_entry = list_head;

    // Initialize next entry
    //
    access_context_t ctx = { .pt = tracer->kpgd, .addr = cur_list_entry, .pt_lookup = true };
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &next_list_entry)) {
        DMSG("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        return TRACER_F;
    }

    /* walk the task list */
    while (1) {
        current_process = cur_list_entry - tracer->os_data.tasks_offset;
    
        ctx.addr = current_process + tracer->os_data.pid_offset;
        tracer_read_32bit(tracer, &ctx, (uint32_t*)&pid);        
        
        /* run cfa for the requested process */
        if (pid == req_pid) {
            return do_cfa(tracer, stack_frames, num_stack_frames, current_process, req_pid, buffer, buflen);
        }

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        ctx.addr = cur_list_entry;
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &next_list_entry)) {
            DMSG("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            return TRACER_F;
        }

        if (cur_list_entry == list_head) {
            break;
        }
    }

    // Failed to find the requested PID
    //
    return TRACER_F;
}