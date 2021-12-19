#include "tracer.h"

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

    // DMSG("--ARM AArch64 PTLookup: vaddr = 0x%.16"PRIx64", pt = 0x%.16"PRIx64"\n", vaddr, pt);    

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
        // levels = va_width == 39 ? 3 : 4;
        levels = 4;
    else if ( PS_64KB == ps )
        levels = va_width == 42 ? 2 : 3;
    else {
        IMSG("16KB granule size ARM64 lookups are not yet implemented\n");
        goto done;
    }

    if ( 4 == levels ) {
        get_zero_level_4kb_descriptor(tracer, pt, vaddr, info);
        // DMSG("--ARM AArch64 PTLookup: zld_value = 0x%"PRIx64"\n",
        //         info->arm_aarch64.zld_value);

        if ( (info->arm_aarch64.zld_value & BIT_MASK(0,1)) != 0b11)
            goto done;

        pt = info->arm_aarch64.zld_value & BIT_MASK(12,47);
        --levels;
    }

    if ( 3 == levels) {
        if ( PS_4KB == ps ) {
            get_first_level_4kb_descriptor(tracer, pt, vaddr, info);
            // DMSG("--ARM AArch64 4kb PTLookup: fld_value = 0x%"PRIx64"\n", info->arm_aarch64.fld_value);

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
            // DMSG("--ARM AArch64 64kb PTLookup: fld_value = 0x%"PRIx64"\n", info->arm_aarch64.fld_value);

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
            // DMSG("--ARM AArch64 4kb PTLookup: sld_value = 0x%"PRIx64"\n", info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_4kb_descriptor(tracer, vaddr, info);
                    // DMSG("--ARM AArch64 4kb PTLookup: tld_value = 0x%"PRIx64"\n", info->arm_aarch64.tld_value);

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
            // DMSG("--ARM AArch64 64kb PTLookup: sld_value = 0x%"PRIx64"\n", info->arm_aarch64.sld_value);

            switch (info->arm_aarch64.sld_value & BIT_MASK(0,1)) {
                case 0b11:
                    get_third_level_64kb_descriptor(tracer, vaddr, info);
                    // DMSG("--ARM AArch64 64kb PTLookup: tld_value = 0x%"PRIx64"\n", info->arm_aarch64.tld_value);

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
    // DMSG("--ARM PTLookup: PA = 0x%"PRIx64"\n", info->paddr);
    return status;
}

status_t pagetable_lookup(tracer_t* tracer, addr_t pt, addr_t vaddr, addr_t *paddr)
{
	page_info_t info;

	if (TRACER_F == v2p_aarch64(tracer, pt, vaddr, &info))
		return TRACER_F;

	*paddr = info.paddr;

	// TODO: cache
	// v2p_cache_set(tracer, vaddr, pt, 0, info.paddr);

	return TRACER_S;
}

status_t get_gpd(tracer_t* tracer, addr_t process, addr_t* out) {
    addr_t ptr;
    addr_t pgd_va;
    access_context_t ctx = { .pt = tracer->kpgd, .addr = process + tracer->os_data.mm_offset, .pt_lookup = true };
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &ptr)) {
        return TRACER_F;
    }

    if (!ptr) {
        ctx.addr = process + tracer->os_data.mm_offset + 8;
        if (TRACER_F == tracer_read_addr(tracer, &ctx, &ptr)) {
            return TRACER_F;
        }
    }

    ctx.addr = ptr + tracer->os_data.pgd_offset;
    if (TRACER_F == tracer_read_addr(tracer, &ctx, &pgd_va)) {
        return TRACER_F;
    }

    if (TRACER_F == pagetable_lookup(tracer, tracer->kpgd, pgd_va, out))
		return TRACER_F;

    return TRACER_S;
}
