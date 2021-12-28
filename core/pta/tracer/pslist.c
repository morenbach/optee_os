#include "tracer.h"

status_t process_list(tracer_t* tracer) {
    char procname[16];
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
            return TRACER_F;
        } 

        /* print out the process name */
        IMSG("[INFO] [%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);

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