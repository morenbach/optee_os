#include "tracer.h"

#ifdef LINUX_BUILD
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define MEMORY_DEVICE  ("/dev/fmem")

bool valid_region(tracer_t* tracer, paddr_t pa, size_t len) {       
    for (int i=0;i<tracer->mem_region_arr_size;i++) {
        if (pa > tracer->mem_region_start_arr[i] && ((pa + len) < tracer->mem_region_end_arr[i])) {
            return true;
        }
    }

    return false;
}

#endif

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

	    // char *p = NULL;
        paddr_t pa = (pfn << tracer->page_shift);


#ifdef LINUX_BUILD
        if (!valid_region(tracer, pa, read_len)) {
            goto done;
        }
        
        int result;
        // unsigned char* tmp_buf = NULL;
        do {
            result = open(MEMORY_DEVICE, O_RDONLY);
        } while (result == -1 && errno == EINTR);
        if (result == -1) goto done;

        int mem_device = result;

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
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (mem_device != -1) {
                        close(mem_device);
                    }

                    goto done;
                }
            }
        }
        
        close(mem_device);
        mem_device = -1;
#elif defined VIRT_BUILD
        // send request over untrsted buffer                
        memcpy(&g_virt_host_buffer[1], &d, sizeof(uintptr_t));
        memcpy(&g_virt_host_buffer[1+sizeof(uintptr_t)], &w, sizeof(size_t));
        // mark request as ready 
        asm volatile("": : :"memory"); // Compile read-write barrier 
        *g_virt_host_buffer = 1;

        // wait until response is ready with a flag there
        while (*g_virt_host_buffer == 1) {  
            // Pause instruction to prevent excess processor bus usage 
            asm volatile("yield\n": : :"memory");
        }

        unsigned char* d = (unsigned char*)buf + (addr_t)buf_offset;
        memcpy(d, &g_virt_host_buffer[1], read_len);
#else
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

	    char* p = (char*)tee_mm_get_smem(mmentry);

		if (!p) {
			ret = TRACER_F;
			goto done;
        }            

        memmove((char*)buf + (addr_t)buf_offset, p + (addr_t)offset, read_len);		

		// unmap range
        core_mmu_unmap_pages((vaddr_t)p, 1);
	    tee_mm_free(mmentry);
#endif

        count -= read_len;
        buf_offset += read_len;
    }

    ret = TRACER_S;

done:
    if (bytes_read)
        *bytes_read = buf_offset;

    return ret;
}

