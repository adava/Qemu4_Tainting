#define TARGET_PAGE_BITS 12
typedef signed char  int8_t;
typedef signed short int16_t;
typedef signed int   int32_t;
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;

#define PAGE_SIZE_BITS TARGET_PAGE_BITS
#define NUM_PAGES_BITS (32 - PAGE_SIZE_BITS)
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define OFFSET_MASK  (PAGE_SIZE - 1)
#define PAGE_MASK  ((1 << NUM_PAGES_BITS) - 1)
#define SHD_find_offset(vaddr) (uint32_t)(vaddr & OFFSET_MASK)
#define SHD_PAGE_INDEX(vaddr) (vaddr >> PAGE_SIZE_BITS)
#define SHD_find_page_addr(vaddr) (SHD_PAGE_INDEX(vaddr) & PAGE_MASK)
#define SHD_KEY_CONVERSION(addr) ((gconstpointer)addr)

#define GLOBAL_POOL_SIZE 124 //X86 registers plus a bunch more allocated temps

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
} shadow_memory;

enum shadow_type{
    TEMP,
    GLOBAL,
    MEMORY
};

typedef struct inquiry_addr{
    union{
        unsigned long vaddr;
        int id;
    }addr;
    enum shadow_type type;
    uint8_t size;
} shad_inq;

typedef int shadow_err;

typedef uint64_t SHD_value;

shadow_memory SHD_Memory;

void SHD_init();

int SHD_map_reg(int reg_code); //returns internal ID assignment for CPU registers; change to be a MACRO

guint SHD_ghash_addr(gconstpointer key);

SHD_value SHD_get_shadow(shad_inq inq); // based on type, it would inquiry shadow_memory. The caller would fetch the proper value based on the size
shadow_err SHD_set_shadow(shad_inq *inq, void *value); //id for temps would be set by the callee

