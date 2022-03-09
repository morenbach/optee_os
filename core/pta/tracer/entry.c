// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>

#include <config.h>
#include <kernel/early_ta.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <tee/uuid.h>
#include <user_ta_header.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <mm/tee_pager.h>
#include "tracer.h"

// typedef struct {
// 	int req_pid;
// 	uint64_t* stack_frames;
// 	int num_stack_frames;
// 	char* buffer;
// 	unsigned int buflen;
// } tracer_cfa_args;

// typedef struct {
// 	char* buffer;
// 	unsigned int buflen;
// } tracer_civ_args;

/*
 * Trusted Application Entry Points
 */
static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
    // tracer_cfa_args* cfa_args;
    // tracer_civ_args* civ_args;

    const uint32_t expected_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE);

	switch (cmd) {
		case TRACER_CMD_CREATE:
            create_tracer(params[0].memref.buffer, params[0].memref.size);
            return TEE_SUCCESS;	
	case TRACER_CMD_CONTROL_FLOW:
	    if (TRACER_S == track_control_flow(params[1].memref.buffer)) {
		    return TEE_SUCCESS;
	    }

	    return TEE_ERROR_BAD_STATE;
        case TRACER_CMD_CIV:
            if (expected_param_types != ptypes) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            DMSG("GOT CIV REQ: 0x%p, %u\n", params[0].memref.buffer, params[0].memref.size);

            if (TRACER_S == trace_civ(params[0].memref.buffer, params[0].memref.size)) {
                return TEE_SUCCESS;
            }            

            return TEE_ERROR_BAD_STATE;
        case TRACER_CMD_CFA:
            if (expected_param_types != ptypes) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            DMSG("GOT CFA REQ: 0x%p, %u\n", params[0].memref.buffer, params[0].memref.size);

            if (TRACER_S == trace_cfa(params[2].value.a, params[1].memref.buffer, params[1].memref.size, params[0].memref.buffer, params[0].memref.size)) {
                return TEE_SUCCESS;
            }

            return TEE_ERROR_BAD_STATE;
        case TRACER_CMD_PSLIST:
            trace_pslist();
            return TEE_SUCCESS;    
	default:
		break;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_TRACER_UUID, .name = PTA_TRACER_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
