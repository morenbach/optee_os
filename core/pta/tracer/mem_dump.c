#include "tracer.h"

status_t dump_vma(tracer_t* tracer, addr_t start_addr,addr_t end_addr, addr_t process_gpd);
status_t dump_memory_map(tracer_t* tracer, addr_t process, addr_t memory_map);
status_t mem_dump_process(tracer_t* tracer, addr_t process, pid_t pid);



status_t dump_vma(tracer_t* tracer, addr_t start_addr,addr_t end_addr, addr_t process_gpd) {
    char page_content[0x1000] = {0};
    start_addr &= ~0xfff;
    int count = 0;

    for (addr_t page_addr = start_addr; page_addr < end_addr; page_addr += 0x1000) {
        access_context_t ctx = { .pt = process_gpd, .addr = page_addr, .pt_lookup = true };
        size_t bytes_read;
        if (TRACER_F == tracer_read(tracer, &ctx, 0x1000, page_content, &bytes_read) || bytes_read != 0x1000) {
            continue;
        }

        count++;

        // now dump the page
        //            
        // DMSG("[0x%lx] ", page_addr);
        // for (int i = 0; i < 0x1000; i++) {
        //     DMSG("0x%x", page_content[i]);
        // }

        // printf("\n");
    }

    IMSG("VMA 0x%lx 0x%lx count=%d\n", start_addr, end_addr, count);
 
    return TRACER_S;
}

status_t dump_memory_map(tracer_t* tracer, addr_t process, addr_t memory_map) {
    addr_t vm_area_struct_addr = 0;
    addr_t process_gpd;

    if (TRACER_F == get_gpd(tracer, process, &process_gpd)) {
        return TRACER_F;
    }

    access_context_t ctx = { .pt = tracer->kpgd, .addr = memory_map + tracer->mm_data.mmap, .pt_lookup = true };
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_area_struct_addr)){
        return TRACER_F;
    }    

    while(1) {
        addr_t vma_start;
        addr_t vma_end;

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_start;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_start)){
            return TRACER_F;
        }  

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_end;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_end)){
            return TRACER_F;
        }         

        dump_vma(tracer, vma_start, vma_end, process_gpd);

        /* follow the next pointer */
        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_next;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_area_struct_addr)) {
            return TRACER_F;
        }

        // Traversal completed, exit the loop
        //
        if(vm_area_struct_addr == 0){        
            return TRACER_S; 
        }  
    }       
    
    return TRACER_S;
}

status_t mem_dump_process(tracer_t* tracer, addr_t process, pid_t pid) {
    addr_t memory_map = 0;
    status_t result;
    

    // get memory map for the process
    access_context_t ctx = { .pt = tracer->kpgd, .addr = process + tracer->os_data.mm_offset, .pt_lookup = true };
    result = tracer_read_addr(tracer, &ctx, &memory_map);        
    if(result == TRACER_F || memory_map == 0){
        DMSG("cannot retrieve memory map for process %d\n", pid);
        return TRACER_F;
    }

    result = dump_memory_map(tracer, process, memory_map);
    if (result != TRACER_S){
        return result;
    }

    return TRACER_S;
}

status_t mem_dump(tracer_t* tracer, pid_t req_pid) {
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
        
        /* run mem dump for the process */
        if (pid == req_pid) {
            return mem_dump_process(tracer, current_process, pid);
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

    return TRACER_S;
}