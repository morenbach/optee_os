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
#include <pta_tracer.h>

#include <config.h>
#include <kernel/early_ta.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <tee/uuid.h>
#include <user_ta_header.h>
#include <mm/core_mmu.h>

status_t tracer_read_memory(void* dst_buffer, addr_t src_paddr, size_t count) {	
	size_t pos = 0;
	void *p = NULL;
	size_t len = 0;
	while (pos < count) {
		// map physical memory to our address space so we can memcpy in a sec
		p = core_mmu_map_rti_check(src_paddr + pos, count - pos, &len);
		if (!p)
			return TRACER_F;
		memmove(dst_buffer, p, len);
		pos += len;
		// unmap range
		core_mmu_map_rti_check(0, 0, &len);
	}

	return TRACER_S;
}

status_t tracer_read_pa(tracer_t* tracer, addr_t paddr, size_t count, void *buf, size_t *bytes_read)
{
	access_context_t ctx = { .addr = paddr, .pt_lookup = false };
    return tracer_read(tracer, &ctx, count, buf, bytes_read);
}

status_t tracer_read_addr(tracer_t* tracer, const access_context_t *ctx, addr_t *value)
{
    status_t ret = tracer_read(tracer, ctx, 8, value, NULL);
    return ret;
}

status_t tracer_read_64_pa(tracer_t* tracer, addr_t paddr, uint64_t *value)
{
    return tracer_read_pa(tracer, paddr, 8, value, NULL);
}

status_t tracer_read_32bit(
	tracer_t* tracer,
	const access_context_t *ctx,
    uint32_t * value)
{
	return tracer_read(tracer, ctx, 4, value, NULL);
}

// 0th Level Page Table Index (4kb Pages)
static inline
uint64_t zero_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 39) & BIT_MASK(0,8);
}

// 0th Level Descriptor (4kb Pages)
static inline
void get_zero_level_4kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.zld_location = (dtb & BIT_MASK(12,47)) | (zero_level_4kb_table_index(vaddr) << 3);
    uint64_t zld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.zld_location, &zld_v)) {
        info->arm_aarch64.zld_value = zld_v;
    }
}

static inline
uint64_t first_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 30) & BIT_MASK(0,8);
}

static inline void get_first_level_4kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info);

static inline
uint64_t first_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr >> 42) & BIT_MASK(0,5);
}

static inline void get_first_level_64kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info);

static inline uint64_t second_level_4kb_table_index(uint64_t vaddr);

static inline void get_second_level_4kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info);

static inline
uint64_t second_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr>>29) & BIT_MASK(0,12);
}

static inline void get_second_level_64kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info);

static inline
uint64_t third_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr>>12) & BIT_MASK(0,8);
}

static inline
void get_third_level_4kb_descriptor(tracer_t* tracer, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & BIT_MASK(12,47)) | (third_level_4kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
}

static inline
uint64_t third_level_64kb_table_index(uint64_t vaddr)
{
    return (vaddr>>16) & BIT_MASK(0,12);
}

static inline void get_third_level_64kb_descriptor(tracer_t* tracer, uint64_t vaddr, page_info_t *info);


static inline
void get_first_level_4kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & BIT_MASK(12,47)) | (first_level_4kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }
}

static inline
void get_second_level_64kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & BIT_MASK(16,47)) | (second_level_64kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
}

static inline
void get_third_level_64kb_descriptor(tracer_t* tracer, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.tld_location = (info->arm_aarch64.sld_value & BIT_MASK(16,47)) | (third_level_64kb_table_index(vaddr) << 3);
    uint64_t tld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.tld_location, &tld_v)) {
        info->arm_aarch64.tld_value = tld_v;
    }
}

static inline
void get_second_level_4kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.sld_location = (dtb & BIT_MASK(12,47)) | (second_level_4kb_table_index(vaddr) << 3);
    uint64_t sld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.sld_location, &sld_v)) {
        info->arm_aarch64.sld_value = sld_v;
    }
}

static inline
uint64_t second_level_4kb_table_index(uint64_t vaddr)
{
    return (vaddr>>21) & BIT_MASK(0,8);
}

static inline
void get_first_level_64kb_descriptor(tracer_t* tracer, uint64_t dtb, uint64_t vaddr, page_info_t *info)
{
    info->arm_aarch64.fld_location = (dtb & BIT_MASK(9,47)) | (first_level_64kb_table_index(vaddr) << 3);
    uint64_t fld_v;
    if (TRACER_S == tracer_read_64_pa(tracer, info->arm_aarch64.fld_location, &fld_v)) {
        info->arm_aarch64.fld_value = fld_v;
    }
}

status_t v2p_aarch64 (tracer_t* tracer,
                      addr_t pt,
                      addr_t vaddr,
                      page_info_t *info)
{
	status_t status = TRACER_F;

    DMSG("--ARM AArch64 PTLookup: vaddr = 0x%.16"PRIx64", pt = 0x%.16"PRIx64"\n", vaddr, pt);    

    bool is_pt_ttbr1 = false;
    page_size_t ps;
    uint8_t levels;
    uint8_t va_width;

    // should be asserted?
    if (pt == tracer->kpgd)
        is_pt_ttbr1 = true;

    if ( is_pt_ttbr1 ) {
        ps = tracer->arm64.tg1;
        va_width = 64 - tracer->arm64.t1sz;
    } else {
        ps = tracer->arm64.tg0;
        va_width = 64 - tracer->arm64.t0sz;
    }

    if ( PS_4KB == ps )
        levels = va_width == 39 ? 3 : 4;
    else if ( PS_64KB == ps )
        levels = va_width == 42 ? 2 : 3;
    else {
        IMSG("16KB granule size ARM64 lookups are not yet implemented\n");
        goto done;
    }

    if ( 4 == levels ) {
        get_zero_level_4kb_descriptor(tracer, pt, vaddr, info);
        DMSG("--ARM AArch64 PTLookup: zld_value = 0x%"PRIx64"\n",
                info->arm_aarch64.zld_value);

        if ( (info->arm_aarch64.zld_value & BIT_MASK(0,1)) != 0b11)
            goto done;

        pt = info->arm_aarch64.zld_value & BIT_MASK(12,47);
        --levels;
    }

    if ( 3 == levels) {
        if ( PS_4KB == ps ) {
            get_first_level_4kb_descriptor(tracer, pt, vaddr, info);
            DMSG("--ARM AArch64 4kb PTLookup: fld_value = 0x%"PRIx64"\n", info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & BIT_MASK(0,1)) {
                case 0b11:
                    pt = info->arm_aarch64.fld_value & BIT_MASK(12,47);
                    --levels;
                    break;
                case 0b01:
                    info->size = PS_1GB;
                    info->paddr = (info->arm_aarch64.fld_value & BIT_MASK(30,47)) | (vaddr & BIT_MASK(0,29));
                    status = TRACER_S;
                    goto done;
                default:
                    goto done;
            }

        }
        if ( PS_64KB == ps ) {
            get_first_level_64kb_descriptor(tracer, pt, vaddr, info);
            DMSG("--ARM AArch64 64kb PTLookup: fld_value = 0x%"PRIx64"\n", info->arm_aarch64.fld_value);

            switch (info->arm_aarch64.fld_value & BIT_MASK(0,1)) {
                case 0b11:
                    pt = info->arm_aarch64.fld_value & BIT_MASK(16,47);
                    --levels;
                    break;
                default:
                    goto done;
            }
        }
    }

    if ( 2 == levels ) {
        if ( PS_4KB == ps ) {
            get_second_level_4kb_descriptor(tracer, pt, vaddr, info);
            DMSG("--ARM AArch64 4kb PTLookup: sld_value = 0x%"PRIx64"\n", info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_4kb_descriptor(tracer, vaddr, info);
                    DMSG("--ARM AArch64 4kb PTLookup: tld_value = 0x%"PRIx64"\n", info->arm_aarch64.tld_value);

                    info->size = PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & BIT_MASK(12,47)) | (vaddr & BIT_MASK(0,11));
                    status = TRACER_S;
                    break;
                case 0b01:
                    info->size = PS_2MB;
                    info->paddr = (info->arm_aarch64.sld_value & BIT_MASK(21,47)) | (vaddr & BIT_MASK(0,20));
                    status = TRACER_S;
                    goto done;
                default:
                    goto done;
            }
        }
        if (PS_64KB == ps ) {
            get_second_level_64kb_descriptor(tracer, pt, vaddr, info);
            DMSG("--ARM AArch64 64kb PTLookup: sld_value = 0x%"PRIx64"\n", info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_64kb_descriptor(tracer, vaddr, info);
                    DMSG("--ARM AArch64 64kb PTLookup: tld_value = 0x%"PRIx64"\n", info->arm_aarch64.tld_value);

                    info->size = PS_4KB;
                    info->paddr = (info->arm_aarch64.tld_value & BIT_MASK(16,47)) | (vaddr & BIT_MASK(0,15));
                    status = TRACER_S;
                    goto done;
                case 0b01:
                    info->size = PS_512MB;
                    info->paddr = (info->arm_aarch64.sld_value & BIT_MASK(29,47)) | (vaddr & BIT_MASK(0,28));
                    status = TRACER_S;
                    goto done;
                default:
                    goto done;
            }
        }
    }

done:    
    DMSG("--ARM PTLookup: PA = 0x%"PRIx64"\n", info->paddr);
    return status;
}

status_t pagetable_lookup(tracer_t* tracer, addr_t pt, addr_t vaddr, addr_t *paddr)
{
	/* check if entry exists in the cache */
	// TODO: fixme add caching capabilities
	// if (TRACER_S == v2p_cache_get(tracer, vaddr, pt, npt, paddr)) {

	// 	/* verify that address is still valid */
	// 	uint8_t value = 0;
	// 	if (TRACER_S == pss_read_8_pa(pss, *paddr, &value)) {
	// 		if (valid_npm(npm)) {
	// 			*naddr = *paddr;
	// 			*paddr = ~0ull;
	// 		}

	// 		return TRACER_S;
	// 	}
	// }

	page_info_t info;

	if (TRACER_F == v2p_aarch64(tracer, pt, vaddr, &info))
		return TRACER_F;

	*paddr = info.paddr;

	// TODO: cache
	// v2p_cache_set(tracer, vaddr, pt, 0, info.paddr);

	return TRACER_S;
}

status_t tracer_read(
        tracer_t* tracer,
        const access_context_t *ctx,
        size_t count, // bytes
        void *buf,
        size_t *bytes_read)
{
    status_t ret = TRACER_F;
    size_t buf_offset = 0;
    addr_t start_addr;
    addr_t paddr;
    // addr_t naddr;
    addr_t pfn;
    addr_t offset;
    addr_t pt;
    // page_mode_t pm;
    // addr_t npt;
    // page_mode_t npm;

    pt = ctx->pt;
    // pm = ctx->pm;
    // npt = ctx->npt;
    // npm = ctx->npm;
    start_addr = ctx->addr;
    
    while (count > 0)
    {
        size_t read_len = 0;

		if (ctx->pt_lookup) {
			if (TRACER_S != pagetable_lookup(tracer, pt, start_addr + buf_offset, &paddr)) {
				goto done;	
			}
		}

        pfn = paddr >> tracer->page_shift;
        IMSG("--Reading pfn 0x%lx\n", pfn);

        offset = (tracer->page_size - 1) & paddr;

        if ((offset + count) > tracer->page_size)
            read_len = tracer->page_size - offset;
        else
            read_len = count;

		char* buffer = (char*)buf + (addr_t)buf_offset;
        if (TRACER_F == tracer_read_memory(buffer, (pfn << tracer->page_shift) + (addr_t)offset, read_len)) {
			DMSG("Failed reading memory!!\n");
			ret = TRACER_F;
			goto done;
		}
        
        // memcpy(((char *)buf) + (addr_t)buf_offset, buffer, read_len);

        count -= read_len;
        buf_offset += read_len;
    }

    ret = TRACER_S;

done:
    if (bytes_read)
        *bytes_read = buf_offset;

    return ret;
}

static status_t init_kaslr(tracer_t* tracer)
{
	uint32_t test;
	access_context_t ctx = { .pt = tracer->kpgd, .addr = tracer->init_task, .pt_lookup = true };

	if (TRACER_S == tracer_read_32bit(tracer, &ctx, &test))
	{
		addr_t init_task_symbol_addr = tracer->os_data.init_task_fixed;
		// if (TRACER_F == linux_symbol_to_address(pss, "init_task", NULL, &init_task_symbol_addr)) {
		// 	return TRACER_F;
		// }

		tracer->os_data.kaslr_offset = tracer->init_task - init_task_symbol_addr;
		DMSG("**calculated KASLR offset from pre-defined init_task addr: 0x%" PRIx64"\n", tracer->os_data.kaslr_offset);
		return TRACER_S;
	}

	return TRACER_F;
}

static status_t init_task_kaslr_test(tracer_t* tracer, addr_t page_vaddr)
{
	status_t ret = TRACER_F;
	uint32_t pid = -1;
	addr_t addr = ~0;
	addr_t init_task = page_vaddr + (tracer->init_task & BIT_MASK(0, 11));	
	access_context_t ctx = { .pt_lookup = true, .pt = tracer->kpgd };

	ctx.addr = init_task + tracer->os_data.pid_offset;
	if (TRACER_F == tracer_read_32bit(tracer, &ctx, &pid))
		return ret;

	if (0 != pid)
		return ret;

	ctx.addr = init_task + tracer->os_data.mm_offset;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

	if (0 != addr)
		return ret;

	ctx.addr = init_task + tracer->os_data.tasks_offset;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

	ctx.addr = addr;
	if (TRACER_F == tracer_read_addr(tracer, &ctx, &addr))
		return ret;

	ctx.addr = init_task + tracer->os_data.name_offset;
    char init_task_name[8];    
    size_t bytes_read;
    if (TRACER_F == tracer_read_pa(tracer, ctx.addr, 7, init_task_name, &bytes_read) || bytes_read != 7) 
		return ret;
    init_task_name[7] = '\0';

	if (!strncmp("swapper", init_task_name, 7))
		ret = TRACER_S;

	return ret;
}

static status_t verify_linux_paging(tracer_t* tracer)
{
	if (TRACER_F == init_kaslr(tracer))
		return TRACER_F;

	return init_task_kaslr_test(tracer, tracer->init_task & ~BIT_MASK(0, 11));
}

static status_t is_aarch64_pd(tracer_t* tracer, addr_t pa)
{
        bool rc = false;
        status_t status = TRACER_F;
        size_t i = 0;

        // TODO: in ARM there can be 4KB,16KB,64KB pages.
        uint64_t pdes[PD_ENTRIES];
        addr_t maxframe = MAX_PHYSICAL_ADDRESS >> 12;

        status = tracer_read_pa(tracer, pa, sizeof(pdes), (void *)pdes, NULL);
        if (TRACER_F == status) {
                goto aarch64_pd_exit;
        }

        for (i = 0; i < PD_ENTRIES; ++i)
        {
                uint64_t pde = pdes[i];

                // 5 == NS bit (non-secure), should be off
                if (GET_BIT(pde, 5))
                {
                        rc = false;
                        goto aarch64_pd_exit;
                }

                if ((pde & BIT_MASK(0,1)) != 0b11) {
                        continue;
                }

                addr_t gfn = (pde & (((1ull << 36) - 1) << 12)) >> 12;

                if (0 == gfn || gfn > maxframe)
                {
                        rc = false;
                        goto aarch64_pd_exit;
                }

                rc = true;
        }

aarch64_pd_exit:
        return rc;
}


static status_t find_page_directories(tracer_t* tracer)
{
	// NOTE: page mode is aarch64.
	status_t rc = TRACER_F;
	addr_t candidate;

	// brute force scan the memory for candidate addresses	
	for (candidate = 0x1000; candidate < MAX_PHYSICAL_ADDRESS; candidate += PS_4KB)
	{
		if (is_aarch64_pd(tracer, candidate))
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

static status_t init_tracer(tracer_t* tracer, addr_t va_init_task) {
	// init json stuff.		
	tracer->init_task = canonical_addr(va_init_task);	
	tracer->os_data.init_task_fixed = tracer->init_task;

	tracer->page_shift = 12;
	tracer->page_size = PS_4KB;

	return TRACER_S;
}

static TEE_Result trace_cfa(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    if (type != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Trace CFA has been called");

	// initialize tracer by getting page table location of normal world
	//
	tracer_t tracer;
	// TODO: pass from noraml world or better yet, hard code here.
	addr_t va_init_task = p[0].value.a;
	init_tracer(&tracer, va_init_task);
	find_page_directories(&tracer);

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
		case TRACER_CMD_CFA:
			return trace_cfa(ptypes, params);
	// case STATS_CMD_PAGER_STATS:
	// 	return get_pager_stats(ptypes, params);
	// case STATS_CMD_ALLOC_STATS:
	// 	return get_alloc_stats(ptypes, params);
	// case STATS_CMD_MEMLEAK_STATS:
	// 	return get_memleak_stats(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_TRACER_UUID, .name = PTA_TRACER_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
