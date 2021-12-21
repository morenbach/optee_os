#include "tracer.h"
#include "jWrite.h"
#include "uthash.h"

#define PROTECTION_FLAGS 3
#define SHA256_DIGEST_LENGTH 32

struct paths_set {
    char path[256];            /* key */    
    UT_hash_handle hh;         /* makes this structure hashable */
};

struct paths_set* visited_paths = NULL;

typedef struct
{
    char name;
    uint32_t mask;
} protection_t;

const protection_t linux_protect[PROTECTION_FLAGS] =
{
    {'r', 0x00000001},
    {'w', 0x00000002},
    {'x', 0x00000004},
};

TEE_Result hash_page (const unsigned char* page_content, unsigned int page_length, unsigned char* hash);
status_t hash_vma(tracer_t* tracer, addr_t start_addr,addr_t end_addr, addr_t process_gpd);
status_t analyze_memory_map(tracer_t* tracer, addr_t process, pid_t pid, addr_t memory_map);

TEE_Result hash_page (const unsigned char* page_content, unsigned int page_length, unsigned char* hash)
{    
    // mbedtls_sha256_context ctx;
 
    // mbedtls_sha256_init(&ctx);
    // mbedtls_sha256_starts(&ctx, 0); /* SHA-256, not 224 */
    // mbedtls_sha256_update(&ctx, page_content, page_length);
    // mbedtls_sha256_finish(&ctx, hash);

	TEE_Result res = TEE_SUCCESS;
	void *ctx = NULL;

	// if (!tag || *tag_len < TEE_SHA256_HASH_SIZE) {
	// 	*tag_len = TEE_SHA256_HASH_SIZE;
	// 	return TEE_ERROR_SHORT_BUFFER;
	// }
	// *tag_len = TEE_SHA256_HASH_SIZE;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		return res;
	res = crypto_hash_init(ctx);
	if (res)
		goto out;
	res = crypto_hash_update(ctx, page_content, page_length);
	if (res)
		goto out;
	res = crypto_hash_final(ctx, hash, SHA256_DIGEST_LENGTH);
out:
	crypto_hash_free_ctx(ctx);
	return res;
}

status_t hash_vma(tracer_t* tracer, addr_t start_addr,addr_t end_addr, addr_t process_gpd) {
    unsigned char page_content[0x1000] = {0};
    // page_entry* page_node = NULL;
    unsigned char page_hash[SHA256_DIGEST_LENGTH] = {0};
    start_addr &= ~0xfff;

    int page_index = 0;
	
    for (addr_t page_addr = start_addr; page_addr < end_addr; page_addr += 0x1000) {
        access_context_t ctx = { .pt = process_gpd, .addr = page_addr, .pt_lookup = true };
        size_t bytes_read;
        if (TRACER_F == tracer_read(tracer, &ctx, 0x1000, page_content, &bytes_read) || bytes_read != 0x1000) {
            continue;
        }

        // compute the hash for the page
        //            
        if (hash_page(page_content, 0x1000, page_hash) != TEE_SUCCESS) {
            return TRACER_F; // unexpected error occured
        }

        jwArr_object();
            char hashbuf[SHA256_DIGEST_LENGTH*2+10];
            char page_index_buf[10];
            char* buf2 = hashbuf;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                if (i==0) {
                    buf2 += sprintf(buf2,"0x");
                }

                buf2 += sprintf(buf2, "%02x", page_hash[i]);
            }

            // Add the NULL termination
            //
            // *buf2 = '\0';

            snprintf(page_index_buf, 10, "%d", page_index++);

            jwObj_string(page_index_buf, hashbuf);
        jwEnd();

        // DMSG("[%s] : { %d, ", path, page_index++);
        // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        //     DMSG("0x%x", page_hash[i]);
        // }

        // printf("}\n");
    }
 
    return TRACER_S;
}

status_t analyze_memory_map(tracer_t* tracer, addr_t process, pid_t pid, addr_t memory_map) {
    // addr_t vm_area_struct_head_addr = 0;
    addr_t vm_area_struct_addr = 0;
    addr_t vm_file_addr = 0;
    addr_t dentry_path = 0;
    // char path[256];
    uint32_t dname_len;
    addr_t brk;
    addr_t start_brk;
    addr_t start_stack;

    addr_t start_code;
    addr_t end_code;
    addr_t start_data;
    addr_t end_data;
    addr_t vdso_addr;
    addr_t process_gpd;

    if (TRACER_F == get_gpd(tracer, process, &process_gpd)) {
        return TRACER_F;
    }

    access_context_t ctx = { .pt = tracer->kpgd, .addr = memory_map + tracer->mm_data.mmap, .pt_lookup = true };
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_area_struct_addr)){
        return TRACER_F;
    }    

    ctx.addr = memory_map + tracer->mm_data.brk;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &brk)){
        return TRACER_F;
    }        

    ctx.addr = memory_map + tracer->mm_data.start_brk;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &start_brk)){
        return TRACER_F;
    }

    ctx.addr = memory_map + tracer->mm_data.start_stack;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &start_stack)){
        return TRACER_F;
    }  

    ctx.addr = memory_map + tracer->mm_data.start_code;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &start_code)){
        return TRACER_F;
    }  

    ctx.addr = memory_map + tracer->mm_data.end_code;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &end_code)){
        return TRACER_F;
    }  

    ctx.addr = memory_map + tracer->mm_data.start_data;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &start_data)){
        return TRACER_F;
    }  

    ctx.addr = memory_map + tracer->mm_data.end_data;
    if(TRACER_F == tracer_read_addr(tracer, &ctx, &end_data)){
        return TRACER_F;
    }  

    if(tracer->mm_data.vdso){
        ctx.addr = memory_map + tracer->mm_data.vdso;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vdso_addr)){
            return TRACER_F;
        }  
    }

    // printf("Code section: [Start: 0x%lx] [End: 0x%lx]\n",start_code, end_code);
    // printf("Data section: [Start: 0x%lx] [End: 0x%lx]\n",start_data, end_data);
    // printf("Heap: [Start: 0x%lx] [End: 0x%lx]\n",start_brk, brk);
    // printf("Stack: [Start: 0x%lx]\n",start_stack);

    // vm_area_struct_head_addr = vm_area_struct_addr;
    
    while(1) {
        addr_t vma_start;
        addr_t vma_end;
        addr_t vma_flags;
        size_t bytes_read;
        // memset(path, 0, 256);

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_flags;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_flags)){
            return TRACER_F;
        }  
        
        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_start;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_start)){
            return TRACER_F;
        }  

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_end;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vma_end)){
            return TRACER_F;
        }  

        ctx.addr = vm_area_struct_addr + tracer->vm_area_data.vm_file;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &vm_file_addr)){
            goto next;
        }  

        ctx.addr = vm_file_addr + tracer->file_data.f_path + tracer->path_data.dentry;
        if(TRACER_F == tracer_read_addr(tracer, &ctx, &dentry_path)){
            goto next;
        }

        // ctx.addr = dentry_path + tracer->dentry_data.d_name + tracer->qstr_data.len;
        // if(TRACER_F == tracer_read_32bit(tracer, &ctx, &dname_len)) {
        //     goto next;
        // }

        // DMSG("H6\n");

        ctx.addr = dentry_path + tracer->dentry_data.d_name + tracer->qstr_data.name + 16;
        char* path = tracer_read_str(tracer, &ctx);
        if (NULL == path) {
        // if(TRACER_F == tracer_read(tracer, &ctx, dname_len, path, &bytes_read) || bytes_read != dname_len) {
            goto next;
        }        

        // path[dname_len+1] = '\0';

        struct paths_set* test;
        HASH_FIND_STR(visited_paths, path, test);
        if (test) {
            free(path);
            goto next; // already visited
        }

        // otherwise, add to visited paths
        test = (struct paths_set*)malloc(sizeof(struct paths_set));
        if (!test) {
            free(path);
            return TRACER_F; // out of memory
        }

        strcpy(test->path, path);
        HASH_ADD_STR(visited_paths, path, test);

        // printf("%d %s\n", dname_len, path);        
        jwArr_object();    
            jwObj_string("name", path);
            jwObj_array("hashes");

                hash_vma(tracer, vma_start, vma_end, process_gpd);

            jwEnd(); // end hashes array
        jwEnd();

        free(path);

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

status_t civ_process(tracer_t* tracer, addr_t process, pid_t pid) {
    addr_t memory_map = 0;
    status_t result;

    // get memory map for the process
    access_context_t ctx = { .pt = tracer->kpgd, .addr = process + tracer->os_data.mm_offset, .pt_lookup = true };
    result = tracer_read_addr(tracer, &ctx, &memory_map);        
    if(result == TRACER_F || memory_map == 0){
        DMSG("cannot retrieve memory map for process %d\n", pid);
        return TRACER_F;
    }

    result = analyze_memory_map(tracer, process, pid, memory_map);
    if (result != TRACER_S){
        return result;
    }

    return TRACER_S;
}

status_t civ(tracer_t* tracer, char* buffer, unsigned int buflen) {
    /* go over all processes, similar to pslist's code */
    char procname[16];
    pid_t pid = 0;
    addr_t current_process = 0;
    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    list_head = tracer->os_data.init_task_fixed + tracer->os_data.tasks_offset;
    cur_list_entry = list_head;
    struct paths_set *it, *tmp;
    
    // Initialize next entry
    //
    access_context_t ctx = { .pt = tracer->kpgd, .addr = cur_list_entry, .pt_lookup = true };
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &next_list_entry)) {
        DMSG("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        return TRACER_F;
    }

    jwOpen(buffer, buflen, JW_ARRAY, JW_PRETTY);

    /* walk the task list */
    while (1) {
        current_process = cur_list_entry - tracer->os_data.tasks_offset;

        /* Note: the task_struct that we are looking at has a lot of
         * information.  However, the process name and id are burried
         * nice and deep.  Instead of doing something sane like mapping
         * this data to a task_struct, I'm just jumping to the location
         * with the info that I want.  This helps to make the example
         * code cleaner, if not more fragile.  In a real app, you'd
         * want to do this a little more robust :-)  See
         * include/linux/sched.h for mode details */
        ctx.addr = current_process + tracer->os_data.pid_offset;
        tracer_read_32bit(tracer, &ctx, (uint32_t*)&pid);        

        ctx.addr = current_process + tracer->os_data.name_offset;
        size_t bytes_read;    
        if (TRACER_F == tracer_read(tracer, &ctx, 16, procname, &bytes_read)) {
            DMSG("Failed to find procname\n");
            goto cleanup;
        } 

        /* print out the process name */
        IMSG("[INFO] [%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);

        /* run civ for the process */
        // if (strcmp(procname, "bash") == 0)
        if (civ_process(tracer, current_process, pid) == TRACER_S) {            
            break;
        }        

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        ctx.addr = cur_list_entry;
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &next_list_entry)) {
            DMSG("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            goto cleanup;
        }

        if (cur_list_entry == list_head) {
            break;
        }
    }

    IMSG("[INFO] DONE\n");

    if (jwClose() != JWRITE_OK) {
        return TRACER_F;
    }

    return TRACER_S;
    
cleanup:

    /* free the hash table contents */
    HASH_ITER(hh, visited_paths, it, tmp) {
      HASH_DEL(visited_paths, it);
      free(it);
    }

    jwClose();
    return TRACER_F;
}