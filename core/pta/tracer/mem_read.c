#include "tracer.h"
// #include <unistd.h>
// #include <fcntl.h>
// #include <errno.h>

// #define MEMORY_DEVICE  ("/dev/fmem")

// status_t tracer_read_memory(void* dst_buffer, addr_t src_paddr, size_t count) {	
// 	size_t pos = 0;
// 	void *p = NULL;
// 	size_t len = 0;
   
// 	while (pos < count) {
// 		// map physical memory to our address space so we can memcpy in a sec        
// 		p = core_mmu_map_rti_check(src_paddr + pos, count - pos, &len);
// 		if (!p)
// 			return TRACER_F;
                    
//         memmove(dst_buffer, p, len);
// 		pos += len;
// 		// unmap range
// 		core_mmu_map_rti_check(0, 0, &len);
// 	}

// 	return TRACER_S;
// }

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
	return tracer_read(tracer, ctx, sizeof(uint32_t), value, NULL);
}

status_t tracer_read_16bit(
	tracer_t* tracer,
	const access_context_t *ctx,
    uint16_t * value)
{
	return tracer_read(tracer, ctx, sizeof(uint16_t), value, NULL);
}


char* tracer_read_str(tracer_t* tracer, const access_context_t *ctx) {
    access_context_t _ctx = *ctx;
    addr_t len = 0;
    uint8_t buf[TRACER_4KB];
    size_t bytes_read;
    bool read_more = 1;
    char *ret = NULL;

    do
    {
        size_t offset = _ctx.addr & BIT_MASK(0, 11);
        size_t read_size = TRACER_4KB - offset;

        if (TRACER_F == tracer_read(tracer, &_ctx, read_size, (void *)&buf, &bytes_read) && !bytes_read) {
            return ret;
        }

        size_t read_len = 0;
        for (read_len = 0; read_len < bytes_read; read_len++)
        {
            if (buf[read_len] == '\0')
            {
                read_more = 0;
                break;
            }
        }

        /*
         * Realloc, tack on the '\0' in case of errors and
         * get ready to read the next page.
         */
        char *_ret = realloc(ret, len + read_len + 1);
        if (!_ret)
            return ret;

        ret = _ret;
        memcpy(&ret[len], &buf, read_len);
        len += read_len;
        ret[len] = '\0';
        _ctx.addr += offset;
    } while (read_more);

    return ret;
}

/*
bool valid_region(paddr_t pa, size_t len) {       
    if (pa > 0x80000000 && pa + len < 0x87ffffff) {
        return true;
    }

    if (pa > 0x88001000 && pa + len < 0xf52a3fff) {
        return true;
    }

    if (pa > 0xf5570000 && pa + len < 0xf5a5ffff) {
        return true;
    }

    if (pa > 0xf5c40000 && pa + len < 0xf5c5ffff) {
        return true;
    }

    if (pa > 0xf5f80000 && pa + len < 0xfaf4ffff) {
        return true;
    }

    if (pa > 0xfaf90000 && pa + len < 0xfaf9ffff) {
        return true;
    }

    if (pa > 0xfaff0000 && pa + len < 0xfeffffff) {
        return true;
    }

    if (pa > 0x100000000 && pa + len < 0x47fffffff) {
        return true;
    }

    return false;
}
*/

status_t tracer_read(
        tracer_t* tracer,
        const access_context_t *ctx,
        size_t count, 
        void *buf,
        size_t *bytes_read)
{
    status_t ret = TRACER_F;
    size_t buf_offset = 0;
    addr_t start_addr;
    addr_t paddr;
    addr_t pfn;
    addr_t offset;
    addr_t pt;

    pt = ctx->pt;
    start_addr = ctx->addr;    
    
    while (count > 0)
    {
        size_t read_len = 0;

		if (ctx->pt_lookup) {
			if (TRACER_S != pagetable_lookup(tracer, pt, start_addr + buf_offset, &paddr)) {
				goto done;	
			}
		} else {
            paddr = start_addr + buf_offset;
        }        

        pfn = paddr >> tracer->page_shift;

        offset = (tracer->page_size - 1) & paddr;

        if ((offset + count) > tracer->page_size) {
            read_len = tracer->page_size - offset;
        } else {
            read_len = count;
        }

	    char *p = NULL;
        paddr_t pa = (pfn << tracer->page_shift);
        // map the physical page
        if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, TRACER_4KB)) {
            ret = TRACER_F;
			goto done;
        }

    	tee_mm_entry_t* mmentry = tee_mm_alloc(&tee_mm_shm, TRACER_4KB);
	    if (!mmentry) {
            ret = TRACER_F;
			goto done;
	    }

	    TEE_Result mres = core_mmu_map_pages(tee_mm_get_smem(mmentry), &pa,
				 1, MEM_AREA_NSEC_SHM);
	    if (mres) { // failed
    		tee_mm_free(mmentry);		
            ret = TRACER_F;
			goto done;
	    }

	    p = (void*)tee_mm_get_smem(mmentry);

		if (!p) {
			ret = TRACER_F;
			goto done;
        }            

        memmove((char*)buf + (addr_t)buf_offset, p + (addr_t)offset, read_len);		

		// unmap range
        core_mmu_unmap_pages((vaddr_t)p, 1);
	    tee_mm_free(mmentry);

        count -= read_len;
        buf_offset += read_len;
    }

    ret = TRACER_S;

done:
    if (bytes_read)
        *bytes_read = buf_offset;

    return ret;
}

