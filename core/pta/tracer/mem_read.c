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
    int mem_device = -1;

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
            // IMSG("--[INFO] v2p 0x%lx -> 0x%lx\n", (start_addr + buf_offset), paddr);
		} else {
            paddr = start_addr + buf_offset;
        }        

        pfn = paddr >> tracer->page_shift;
        // IMSG("--Reading pfn 0x%lx\n", pfn);

        offset = (tracer->page_size - 1) & paddr;

        if ((offset + count) > tracer->page_size) {
            read_len = tracer->page_size - offset;
        } else {
            read_len = count;
        }

	    char *p = NULL;
	    // size_t maplen = 0;
        paddr_t pa = (pfn << tracer->page_shift);
/*        
        if (!valid_region(pa, read_len)) {
            goto done;
        }


        int result;
        do {
            result = open(MEMORY_DEVICE, O_RDONLY);
        } while (result == -1 && errno == EINTR);
        if (result == -1) goto done;

        mem_device = result;

        unsigned char   *d = (unsigned char*)buf + (addr_t)buf_offset;
        off_t            o = (off_t)(pa + (addr_t)offset);
        size_t           n = read_len;
        ssize_t          r;

        while (n) {
            r = pread(mem_device, d, n, o);
            if (r == (ssize_t)n) {
                break;
            }
            else {
                if (r >= (ssize_t)0) {
                    d += r;
                    n -= r;
                    o += r;
                    continue;
                }
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) goto done;
            }
        }
        
        close(mem_device);
        mem_device = -1;

*/


        // map the physical page
		// p = core_mmu_map_rti_check((pfn << tracer->page_shift), PS_4KB, &maplen);
        if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, PS_4KB)) {
            ret = TRACER_F;
			goto done;
        }

    	tee_mm_entry_t* mmentry = tee_mm_alloc(&tee_mm_shm, PS_4KB);
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
        
        // if (maplen != PS_4KB) {
        //     DMSG("===========FAILED MAPLEN, unexpected %lu\n", maplen);
        //     ret = TRACER_F;
		// 	goto done;
        // }

        memmove((char*)buf + (addr_t)buf_offset, p + (addr_t)offset, read_len);		
        // IMSG("--Map PA 0x%lx into %p and read into %p from %p/0x%lx sz %lu/%lu\n", pa, p, (char*)buf + (addr_t)buf_offset, p + (addr_t)offset, paddr, read_len, count);

		// unmap range
		// core_mmu_map_rti_check(0, 0, &maplen);
        core_mmu_unmap_pages((vaddr_t)p, 1);
	    tee_mm_free(mmentry);

        count -= read_len;
        buf_offset += read_len;
    }

    ret = TRACER_S;

done:
    if (bytes_read)
        *bytes_read = buf_offset;
    
    // if (mem_device != -1) {
    //     close(mem_device);
    // }

    return ret;
}

