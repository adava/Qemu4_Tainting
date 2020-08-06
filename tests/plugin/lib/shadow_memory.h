#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#define MAX_NUM_FLAGS 64
#define TARGET_PAGE_BITS 12

//#if !defined(_BITS_STDINT_INTN_H) && !defined(SHADOW_BASIC_INT_TYPES)
//#define SHADOW_BASIC_INT_TYPES
//typedef signed char  int8_t;
//typedef signed short int16_t;
//typedef signed int   int32_t;
//typedef unsigned char  uint8_t;
//typedef unsigned short uint16_t;
//typedef unsigned int   uint32_t;
//typedef signed long long   int64_t;
//typedef unsigned long long uint64_t;
//#endif
#define DEREF_TYPE(buf,type) (*(type*)buf)

#define SIZE_SET(buf,size,res)  switch(size){\
                                case SHD_SIZE_u8:\
                                    DEREF_TYPE(buf,uint8_t) =DEREF_TYPE(res,uint8_t);\
                                    break;\
                                case SHD_SIZE_u16:\
                                    DEREF_TYPE(buf,uint16_t)=DEREF_TYPE(res,uint16_t);\
                                    break;\
                                case SHD_SIZE_u32:\
                                    DEREF_TYPE(buf,uint32_t)=DEREF_TYPE(res,uint32_t);\
                                    break;\
                                case SHD_SIZE_u64:\
                                    DEREF_TYPE(buf,uint64_t)=DEREF_TYPE(res,uint64_t);\
                                    break;\
                                default:\
                                   assert(0);\
                                }

#define PAGE_SIZE_BITS TARGET_PAGE_BITS
#define NUM_PAGES_BITS (32 - PAGE_SIZE_BITS)
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define OFFSET_MASK  (PAGE_SIZE - 1)
#define PAGE_MASK  ((1 << NUM_PAGES_BITS) - 1)
#define SHD_find_offset(vaddr) (uint32_t)(vaddr & OFFSET_MASK)
#define SHD_PAGE_INDEX(vaddr) (vaddr >> PAGE_SIZE_BITS)
#define SHD_find_page_addr(vaddr) (vaddr & PAGE_MASK)
#define SHD_KEY_CONVERSION(addr) ((gconstpointer)SHD_PAGE_INDEX(vaddr))
#define SHD_assemble_addr(page, addr) (page << PAGE_SIZE_BITS | addr)

#ifndef GLOBAL_POOL_SIZE
#ifdef X86_REG_ENDING
#define GLOBAL_POOL_SIZE X86_REG_ENDING + 20 //Capstone has 234 X86 registers, we allocate a few more for temps
#else
#define GLOBAL_POOL_SIZE 254
#endif
#endif

#define copy_inq(src, dst)  dst.addr.vaddr = src.addr.vaddr;\
                            dst.type = src.type;\
                            dst.size = src.size;
typedef struct shadow_page_struct {
    uint8_t bitmap[PAGE_SIZE]; /* Contains the bitwise tainting data for the page */
} shadow_page;

//typedef struct shadow_global_pool_struct {
//    uint64_t bitmap[GLOBAL_POOL_SIZE]; /* Contains bitwise tainting data for registers and other globals */
//    struct shadow_global_pool_struct *next;
//} shadow_global;

/* Middle node for holding memory taint information */
typedef struct shadow_memory_struct {
    GHashTable *pages; //it’s a hashmap of shadow_pages
    GPtrArray *global_temps; //initially will have GLOBAL_POOL_SIZE len of uint64_t, and then increases if needed
    uint8_t flags[MAX_NUM_FLAGS]; //according to memcheck, one bit is enough but we don't have memory constraint plus handling bits is complicated
} shadow_memory;

enum shadow_type{
    TEMP = 1, //so we can distinguish uninitialized inquiries
    GLOBAL,
    MEMORY,
    IMMEDIATE, //used for SHIFT, this type MUST not be passed to the shadow storage
    FLAG
};

typedef enum {
    SHD_SIZE_u8= sizeof(uint8_t),
    SHD_SIZE_u16= sizeof(uint16_t),
    SHD_SIZE_u32= sizeof(uint32_t),
    SHD_SIZE_u64= sizeof(uint64_t),
    SHD_SIZE_MAX
} SHD_SIZE;

typedef struct inquiry{
    union{
        uint64_t vaddr;
        int id;
    }addr;
    enum shadow_type type;
    uint8_t size;
} shad_inq;

typedef int shadow_err;

typedef uint64_t SHD_value;

shadow_memory SHD_Memory;

void SHD_init(void);

int SHD_map_reg(int reg_code); //returns internal ID assignment for CPU registers; change to be a MACRO

guint SHD_ghash_addr(gconstpointer key);

static uint64_t convert_value(void *value, uint8_t size);
/* Based on type, it would inquiry shadow_memory. Globals lower bytes will be returned based on the inquiry size. Memory shadows would be read based on the address and size e.g. for a 4 bytes query, it reads 4 bytes from the address.
 The result is always converted to a 8 byte shadow value. */
SHD_value SHD_get_shadow(shad_inq inq);

shadow_err SHD_set_shadow(shad_inq *inq, void *value); //id for temps would be set by the callee

shadow_err write_memory_shadow(uint64_t vaddr, uint32_t size, uint8_t value);

shadow_err check_registers(uint64_t start, uint64_t end);

int SHD_list_mem(GFunc print_mem_shadows); //The first parameter given to the print_mem_shadows is the memory address, and the second is its non-zero shadow value. The first parameter is live until return.
int SHD_list_global(GFunc print_func);
int SHD_list_temp(GFunc print_func);
#endif