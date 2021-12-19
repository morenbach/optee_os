#include <stdio.h>
#include <string.h>
// #include <malloc.h>
#include "tracer.h"
#include "jWrite.h"
#include "symbols.h"

tracer_t g_tracer; 

static status_t init_kaslr(tracer_t* tracer)
{
	uint32_t test;
	access_context_t ctx = { .pt = tracer->kpgd, .addr = tracer->init_task, .pt_lookup = true };

	if (TRACER_S == tracer_read_32bit(tracer, &ctx, &test))
	{
		addr_t init_task_symbol_addr = tracer->os_data.init_task_fixed;

		tracer->os_data.kaslr_offset = tracer->init_task - init_task_symbol_addr;
		// DMSG("**calculated KASLR offset from pre-defined init_task addr: 0x%" PRIx64"\n", tracer->os_data.kaslr_offset);
		return TRACER_S;
	}

	return TRACER_F;
}

static status_t init_task_kaslr_test(tracer_t* tracer, addr_t page_vaddr)
{
    // DMSG("**RUNNING KASLR TEST\n");
	status_t ret = TRACER_F;
	uint32_t pid = -1;
	addr_t addr = ~0;
	addr_t init_task = page_vaddr + (tracer->init_task & BIT_MASK(0, 11));	
	access_context_t ctx = { .pt_lookup = true, .pt = tracer->kpgd };

	ctx.addr = init_task + tracer->os_data.pid_offset;
	if (TRACER_F == tracer_read_32bit(tracer, &ctx, &pid))
		return ret;

    // DMSG("**RUNNING KASLR TEST - READ PID offset\n");

	if (0 != pid)
		return ret;

    // DMSG("**RUNNING KASLR TEST - PID correct\n");

	ctx.addr = init_task + tracer->os_data.mm_offset;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

    // DMSG("**RUNNING KASLR TEST - read mm offset\n");

	if (0 != addr)
		return ret;
    
    // DMSG("**RUNNING KASLR TEST - mm correct\n");

	ctx.addr = init_task + tracer->os_data.tasks_offset;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

    // DMSG("**RUNNING KASLR TEST - read task offset 0x%lx\n", addr);

	ctx.addr = addr;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

    // DMSG("**RUNNING KASLR TEST - task addr read succesfully\n");

	ctx.addr = init_task + tracer->os_data.name_offset;
    char init_task_name[16];    
    size_t bytes_read;    
    if (TRACER_F == tracer_read(tracer, &ctx, 16, init_task_name, &bytes_read)) 
		return ret;

    // DMSG("**RUNNING KASLR TEST - task name read with %lu %s\n", bytes_read, init_task_name);
    init_task_name[7] = '\0';

    // if (bytes_read != 7)
    //     return ret;

	if (!strncmp("swapper", init_task_name, 7))
		ret = TRACER_S;
    
    // DMSG("**RUNNING KASLR TEST - task name correct %s\n", init_task_name);

	return ret;
}

static status_t verify_linux_paging(tracer_t* tracer)
{
	if (TRACER_F == init_kaslr(tracer))
		return TRACER_F;

	return init_task_kaslr_test(tracer, tracer->init_task & ~BIT_MASK(0, 11));
}

// static status_t is_aarch64_pd(tracer_t* tracer, addr_t pa)
// {
//         bool rc = false;
//         status_t status = TRACER_F;
//         size_t i = 0;

//         // TODO: in ARM there can be 4KB,16KB,64KB pages.
//         uint64_t pdes[PD_ENTRIES];
//         addr_t maxframe = MAX_PHYSICAL_ADDRESS >> 12;

//         status = tracer_read_pa(tracer, pa, sizeof(pdes), (void *)pdes, NULL);
//         if (TRACER_F == status) {
//                 goto aarch64_pd_exit;
//         }

//         for (i = 0; i < PD_ENTRIES; ++i)
//         {
//                 uint64_t pde = pdes[i];

//                 // 5 == NS bit (non-secure), should be off
//                 if (GET_BIT(pde, 5))
//                 {
//                         rc = false;
//                         goto aarch64_pd_exit;
//                 }

//                 if ((pde & BIT_MASK(0,1)) != 0b11) {
//                         continue;
//                 }

//                 addr_t gfn = (pde & (((1ull << 36) - 1) << 12)) >> 12;

//                 if (0 == gfn || gfn > maxframe)
//                 {
//                         rc = false;
//                         goto aarch64_pd_exit;
//                 }

//                 rc = true;
//         }

// aarch64_pd_exit:
//         return rc;
// }


static status_t find_page_directories(tracer_t* tracer)
{
	// NOTE: page mode is aarch64.
	status_t rc = TRACER_F;
	addr_t candidate;

    // tracer->kpgd = 0x812da000;
    // if (TRACER_S == verify_linux_paging(tracer))
    // {
    //     rc = TRACER_S;
    //     DMSG("Found PGD candidate 0x%lx\n", candidate);        
    // }
    // return rc;

	// brute force scan the memory for candidate addresses	
	for (candidate = 0x1000; candidate < MAX_PHYSICAL_ADDRESS; candidate += PS_4KB)
	{        
		// if (is_aarch64_pd(tracer, candidate))
		{
			tracer->kpgd = candidate;
			if (TRACER_S == verify_linux_paging(tracer))
			{
				rc = TRACER_S;
				DMSG("Found PGD candidate 0x%lx\n", candidate);
				break;
			}
		}
	}
	return rc;
}

void create_tracer(void) {
	// DMSG("Trace CFA has been called\n");

	// initialize tracer by getting page table location of normal world
	//
	init_symbols(&g_tracer);

    // DMSG("Init tracer done\n");
    // addr_t c = p[0].value.b;    
    // c <<= 32;
    // c += p[0].value.a;
	// find_page_directories(&tracer, c);
	if (find_page_directories(&g_tracer) == TRACER_F) {
        return;
    }

    // Run a simple process list forensic for a sanity check
    //
    // process_list(&tracer);

    // Run simple CIV
    //
    // civ(&tracer);

    // Run memory dump
    //
    // mem_dump(&tracer, 3148041);

    // Run CFA
    //
    // cfa(&tracer, 3148041);

    // if (type != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
    //                 TEE_PARAM_TYPE_NONE,
    //                 TEE_PARAM_TYPE_NONE,
    //                 TEE_PARAM_TYPE_NONE)) {
    //     return TEE_SUCCESS;
    // }

	// return TEE_SUCCESS;
}


void trace_cfa(int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen) {
    cfa(&g_tracer, req_pid, stack_frames, num_stack_frames, buffer, buflen);    
}

void trace_civ(char* buffer, unsigned int buflen) {
    civ(&g_tracer, buffer, buflen);
}