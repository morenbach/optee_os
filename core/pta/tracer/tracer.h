/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef __PTA_TRACER_H
#define __PTA_TRACER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "optee.h"

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_TRACER_UUID { 0xd5a2471a, 0x3ae9, 0x11ec, \
		{ 0x8d, 0x3d, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03 } }

#define PTA_TRACER_NAME		"tracer.ta"

/*
 * Trace CFA, TODO: document me
 *
 * [out]     memref[0]        Array of device UUIDs
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define TRACER_CMD_CFA	0x0 /* after tee-supplicant run */

#define GET_BIT(reg, bit) (!!(reg & (1ULL<<bit)))
#define BIT_MASK(a, b) (((unsigned long long) -1 >> (63 - (b))) & ~((1ULL << (a)) - 1))

#define ACCESS_CONTEXT(C, ...)                  \
    access_context_t C = {                      \
        .version = ACCESS_CONTEXT_VERSION,      \
        __VA_ARGS__                             \
    }

// TODO: fix this const value - bug prone.
#define MAX_PHYSICAL_ADDRESS 524288000000

typedef uint64_t addr_t;
typedef int32_t pid_t;

/* ENUMS */
typedef enum status {
    TRACER_S,  
    TRACER_F   
} status_t;

typedef enum page_size {
    PS_UNKNOWN  = 0ULL,         
    PS_1KB      = 0x400ULL,     
    PS_4KB      = 0x1000ULL,    
    PS_16KB     = 0x4000ULL,    
    PS_64KB     = 0x10000ULL,   
    PS_1MB      = 0x100000ULL,  
    PS_2MB      = 0x200000ULL,  
    PS_4MB      = 0x400000ULL,  
    PS_16MB     = 0x1000000ULL, 
    PS_32MB     = 0x2000000ULL, 
    PS_512MB    = 0x20000000ULL,  
    PS_1GB      = 0x40000000ULL,  
} page_size_t;


/* STRUCTS */

typedef struct {   
	bool pt_lookup; 
    union {
        struct {
            addr_t addr; 

            union {
                addr_t pt;         
                addr_t page_table; 
                addr_t dtb;        
                pid_t pid;     
            };
        };

        const char *ksym; 
    };
} access_context_t;


typedef struct {
    addr_t mmap;  /* list of memory areas */
    addr_t start_brk; /* start address of heap */
    addr_t brk; /* end address of heap */
    addr_t start_stack; /* start address of stack */
    addr_t start_code; /* start address of code */
    addr_t end_code; /* end address of code */
    addr_t start_data; /* start address of data */
    addr_t end_data;  /* end address of data */
    addr_t vdso; /* vdso address */
}  mm_struct_t;

typedef struct {
    addr_t vm_pgoff;
    addr_t vm_start;
    addr_t vm_end;
    addr_t vm_file;
    addr_t vm_page_prot;
    addr_t vm_flags;
    addr_t vm_next;
} vm_area_struct_t;

typedef struct {
    addr_t f_inode;
    addr_t f_owner;
    addr_t f_path;
} file_struct_t;

typedef struct {
    addr_t dentry;
} path_struct_t;

typedef struct {
    addr_t d_name;    
} dentry_struct_t;

typedef struct {
    addr_t name;
    addr_t len;
} qstr_struct_t;

typedef struct {
    addr_t e_phnum;
    addr_t e_phentsize;
    addr_t e_phoff;
} elf64_hdr_struct;

typedef struct {
    addr_t p_type;
    addr_t p_offset;
    addr_t p_vaddr;
} elf64_phdr_struct;

typedef struct {
    addr_t st_name;
    addr_t st_value;
} elf64_sym_struct;

typedef struct {
    addr_t r_addend;
    addr_t r_info;
    addr_t r_offset;
} elf64_rela_struct;

typedef struct {
    char *sysmap; /**< system map file for domain's running kernel */

    addr_t tasks_offset; /**< task_struct->tasks */

    addr_t mm_offset; /**< task_struct->mm */

    addr_t pid_offset; /**< task_struct->pid */

    addr_t pgd_offset; /**< mm_struct->pgd */

    addr_t name_offset; /**< task_struct->comm */

    addr_t kaslr_offset; /**< offset generated at boot time for KASLR */

    addr_t init_task_fixed; /**< Rekall's location for init task, ignoring KASLR */

    addr_t swapper_pg_dir; /**< swapper_pg_dir for file mode initR */

    addr_t kernel_pgt; /**< kernel_pgt for file mode init */
    
    addr_t boundary; /**< boundary for file mode init */

    addr_t phys_start; /**< phys_start for file mode init */

    addr_t virt_start; /**< virt_start for file mode init */
    
} linux_instance_t;

typedef struct
{    
	addr_t kpgd;
	addr_t init_task;
	uint32_t page_shift;
	uint32_t page_size;
	linux_instance_t os_data;
    mm_struct_t mm_data;
    vm_area_struct_t vm_area_data;
    file_struct_t file_data;
    path_struct_t path_data;
    dentry_struct_t dentry_data;
    qstr_struct_t qstr_data;
    elf64_hdr_struct elf64_hdr_data;
    elf64_phdr_struct elf64_phdr_data;
    elf64_sym_struct elf64_sym_data;
    elf64_rela_struct elf64_rela_data;

	union
	{
		struct
		{
			bool pse;
			bool transition_pages;
		} x86;

		struct
		{
			int t0sz;
			int t1sz;
			page_size_t tg0;
			page_size_t tg1;
		} arm64;
	};
} tracer_t;

typedef struct page_info {
    addr_t vaddr;       
    addr_t paddr;       
    // addr_t naddr;       

    page_size_t size;   
    // page_size_t nsize;  

    addr_t pt;          
    // page_mode_t pm;     

    // addr_t npt;         
    // page_mode_t npm;    

    union {
        struct {
            uint32_t fld_location;
            uint32_t fld_value;
            uint32_t sld_location;
            uint32_t sld_value;
        } arm_aarch32;

        struct {
            uint64_t zld_location;
            uint64_t zld_value;
            uint64_t fld_location;
            uint64_t fld_value;
            uint64_t sld_location;
            uint64_t sld_value;
            uint64_t tld_location;
            uint64_t tld_value;
        } arm_aarch64;
    };
} page_info_t;

/* IMPLEMENT ME LATER */
#define v2p_cache_init(...)     NOOP
#define v2p_cache_destroy(...)  NOOP
#define v2p_cache_set(...)      NOOP
#define v2p_cache_flush(...)    NOOP
#define v2p_cache_get(...) TRACER_F
#define v2p_cache_del(...) TRACER_F

#define pid_cache_init(...)     NOOP
#define pid_cache_destroy(...)  NOOP
#define pid_cache_set(...)      NOOP
#define pid_cache_flush(...)    NOOP
#define pid_cache_get(...) TRACER_F
#define pid_cache_del(...) TRACER_F

#define rva_cache_init(...)     NOOP
#define rva_cache_destroy(...)  NOOP
#define rva_cache_set(...)      NOOP
#define rva_cache_flush(...)    NOOP
#define rva_cache_get(...) TRACER_F
#define rva_cache_del(...) TRACER_F

#define sym_cache_init(...)     NOOP
#define sym_cache_destroy(...)  NOOP
#define sym_cache_set(...)      NOOP
#define sym_cache_flush(...)    NOOP
#define sym_cache_get(...) TRACER_F
#define sym_cache_del(...) TRACER_F

#define CANONCAL_ADDR GET_BIT(va, 47) ? (va | 0xffff000000000000) : va
#define PD_ENTRIES (PS_4KB / sizeof(uint64_t))

static inline addr_t
canonical_addr(addr_t va)
{
	return CANONCAL_ADDR;
}


/* Function declarations */

status_t tracer_read_memory(void* dst_buffer, addr_t src_paddr, size_t count);
status_t tracer_read(
        tracer_t* tracer,
        const access_context_t *ctx,
        size_t count, // bytes
        void *buf,
        size_t *bytes_read);
status_t tracer_read_pa(tracer_t* tracer, addr_t paddr, size_t count, void *buf, size_t *bytes_read);
status_t tracer_read_64bit_pa(tracer_t* tracer, addr_t paddr, uint64_t *value);
status_t v2p_aarch64 (tracer_t* tracer,
                      addr_t pt,
                      addr_t vaddr,
                      page_info_t *info);

status_t tracer_read_16bit(
	tracer_t* tracer,
	const access_context_t *ctx,
    uint16_t * value);

status_t tracer_read_32bit(
	tracer_t* tracer,
	const access_context_t *ctx,
    uint32_t * value);

status_t tracer_read_64_pa(
        tracer_t* tracer,
        addr_t paddr,
        uint64_t *value);

status_t tracer_read_addr(tracer_t* tracer, const access_context_t *ctx, addr_t *value);

status_t pagetable_lookup(tracer_t* tracer, addr_t pt, addr_t vaddr, addr_t *paddr);

status_t process_list(tracer_t* tracer);
status_t get_gpd(tracer_t* tracer, addr_t process, addr_t* out);

status_t civ(tracer_t* tracer, char* buffer, unsigned int buflen);
status_t cfa(tracer_t* tracer, int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen);
status_t mem_dump(tracer_t* tracer, pid_t req_pid);

void create_tracer(void);
void trace_cfa(int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen);
void trace_civ(char* buffer, unsigned int buflen);

#ifdef __cplusplus
}
#endif


#endif /* __PTA_TRACER_H */
