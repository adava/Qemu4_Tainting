//
// Created by sina on 4/15/20.
//
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "../lib/utility.h"
#include "shadow_memory.h"

#ifdef DEBUG_ON
#define DEBUG_TAINT_SOURCE(inq, value)     if (value!=0){\
                                                    printf("inquiry is tainted => inq.type=%d, addr/id=0x%lx, size=%d\n",inq->type,inq->addr.vaddr,inq->size);\
                                                    assert(0);}
#else
#define DEBUG_TAINT_SOURCE(inq, value)
#endif

shadow_page *find_shadow_page(uint64_t vaddr); // would get the higher part of the address and searches SHD_Memory pages for the inquiry page

void *get_shadow_memory(uint64_t vaddr); //the entire memory is addressable, plus this is an internal function. The caller fetches properly

SHD_value *get_shadow_global(int id); //would return temps as well, the storage is in sizeof(SHD_value) so the caller must fetch the correct chunk

shadow_err set_memory_shadow(uint64_t vaddr, uint8_t size, void *value);

shadow_err set_global_shadow(int id, uint8_t size, void *value);

shadow_err set_temp_shadow(int *id, uint8_t size, void *value); //would return the inserted id

void SHD_initialize_globals(void);

guint SHD_ghash_addr(gconstpointer key){
    uint64_t h = (uint64_t)key;
    h = SHD_find_page_addr(h);
//  printf("in SHD_ghash_addr, key=%llx, h=%llx\n",(uint64_t)key,h);
    return ((guint)h);
}

static inline uint64_t convert_value(void *value, uint8_t size){
    SHD_value temp;
    switch(size){ //dereference value argument based on the passed value size (read based on size but assign to SHD_value)
        case 1:
            temp = (SHD_value)(*(uint8_t *)value); //change to a memcpy
            break;
        case 2:
            temp = (SHD_value)(*(uint16_t*)value);
            break;
        case 4:
            temp = (SHD_value)(*(uint32_t*)value);
            break;
        case 8:
            temp = (SHD_value)(*(uint64_t*)value);
            break;
        default:
            printf("unknown size=%d for conversion!\n", size);
            assert(0);
            break;
    }
    return temp;
}

void SHD_initialize_globals(void){
    for(int i=0;i<GLOBAL_POOL_SIZE;i++){
        SHD_value *shadow = g_new0(SHD_value,1); //would initialize to zero
        g_ptr_array_add(SHD_Memory.global_temps,shadow);
    }
    memset(SHD_Memory.flags,0,MAX_NUM_FLAGS);
}

void SHD_init(void){
    SHD_Memory.pages = g_hash_table_new_full(SHD_ghash_addr, g_direct_equal, NULL, NULL);
    SHD_Memory.global_temps = g_ptr_array_new_full(GLOBAL_POOL_SIZE,NULL);
    SHD_initialize_globals();
}

shadow_page *find_shadow_page(uint64_t vaddr){
    shadow_page *page = g_hash_table_lookup (SHD_Memory.pages,SHD_KEY_CONVERSION(vaddr));
    return page;
}

SHD_value *get_shadow_global(int id){
    SHD_value *shadow = NULL;
    int rid = id;
    if(id>R_HIGH && id<R_EXTRA){ //handling higher parts of the general registers
        rid -=R_HIGH+1;
    }
    shadow = g_ptr_array_index(SHD_Memory.global_temps, rid);
    if(rid!=id){
        shadow = (SHD_value *)(((uint8_t *)(shadow))+1);
    }
    return shadow;
}

void *get_shadow_memory(uint64_t vaddr){
    shadow_page *page = find_shadow_page(vaddr);
    if(page==NULL){
        return NULL;
    } else{
        return &page->bitmap[SHD_find_offset(vaddr)];
    }
}

static void *get_flags_shadow(int id){
    return &SHD_Memory.flags[id];
}

SHD_value SHD_get_shadow(shad_inq inq){
    void *shv;
    SHD_value rval=0;
//    void *g_addr = NULL;
    switch (inq.type){
        case MEMORY:
            shv = get_shadow_memory(inq.addr.vaddr);
            break;
        case FLAG:
            shv = get_flags_shadow(inq.addr.id); //the return value is flag size, cast would not be automatically applied.
            break;
        case GLOBAL:
            if (inq.addr.id>=GLOBAL_POOL_SIZE){
                printf("ERROR: Global ID greater than the pool size\n");
//        assert(0);
            }
        case TEMP:
            shv = get_shadow_global(inq.addr.id);
            break;
        default:
            printf("inq.type=%d\n",inq.type);
            assert(0);
    }
    rval = shv!=NULL?convert_value(shv,inq.size):0;
//    printf("shv=%p, ind=%d, g_addr=%p, shadow=0x%llx\n",shv,g_ind,g_addr,*(SHD_value*)shv);
    DEBUG_TAINT_SOURCE(&inq,rval)
    return rval;
}

shadow_err set_temp_shadow(int *id, uint8_t size, void *value){
    SHD_value *shadow = g_new0(SHD_value,1); //would initialize to zero
    g_ptr_array_add(SHD_Memory.global_temps,shadow);
    *shadow = convert_value(value, size);
    assert(SHD_Memory.global_temps->len>=GLOBAL_POOL_SIZE);
    *id = SHD_Memory.global_temps->len-1;
    return 0;
}

shadow_err set_global_shadow(int id, uint8_t size, void *value){ // Big/Little Endian problems might occur. Assumes Big Endian here
    assert(id<GLOBAL_POOL_SIZE);
    int rid = id;
    if(id>R_HIGH && id<R_EXTRA){
        rid -=R_HIGH+1;
    }
    SHD_value *shadow = get_shadow_global(rid); //get the reference
    assert(shadow!=NULL);
    if(rid!=id){
        shadow = (SHD_value *)(((uint8_t *)(shadow))+1);
    }
    SIZE_SET((shadow),size,value)
    //printf("shadow_ptr=%p, ind=%d, value=0x%lx, shadow=%llx\n",shadow,0,*(SHD_value *)value,*(SHD_value*)shadow);
    //*shadow = convert_value(value, size); //assignment
    return 0;
}

shadow_err set_memory_shadow(uint64_t vaddr, uint8_t size, void *value){ //should check the size would not surpass a page
    shadow_page *page = find_shadow_page(vaddr);
    if (page==NULL){
        page = g_new0(shadow_page,1);
        g_hash_table_insert(SHD_Memory.pages,(gpointer)(SHD_KEY_CONVERSION(vaddr)),page);
    }
    memcpy(&(page->bitmap[SHD_find_offset(vaddr)]),value,size);
    return 0;
}

//bulk copy
shadow_err write_memory_shadow(uint64_t vaddr, uint32_t size, uint8_t value){ //check the size
    uint64_t page_bound = (vaddr & ~OFFSET_MASK)+PAGE_SIZE;

    if (size + vaddr>page_bound){
        printf("vaddr=0x%lx, write size=%d exceeds page boundary=0x%lx\n",vaddr,size,page_bound);
        return 1;
        //assert(0);
    }
    shadow_page *page = find_shadow_page(vaddr);
    if (page==NULL){
        page = g_new0(shadow_page,1);
        g_hash_table_insert (SHD_Memory.pages,(gpointer)(SHD_KEY_CONVERSION(vaddr)),page);
    }
//    printf("vaddr_of=0x%llx, write_size=%d\n",SHD_find_offset(vaddr),size);
    memset(&(page->bitmap[SHD_find_offset(vaddr)]),value,size);
//    printf("vaddr_of=0x%x, value=0x%x\n",0x800e,page->bitmap[SHD_find_offset(0x800e)]);
    return 0;
}

static inline shadow_err set_flags_shadow(int id, void *value){
    SHD_Memory.flags[id] = *((uint8_t*)value);
    return 0;
}

shadow_err SHD_set_shadow(shad_inq *inq, void *value){
    shadow_err res=0;
    DEBUG_TAINT_SOURCE(inq,*(uint64_t *)(value))
    switch (inq->type){
        case MEMORY:
            res=set_memory_shadow(inq->addr.vaddr,inq->size,value);
            break;
        case GLOBAL:
            res = set_global_shadow(inq->addr.id,inq->size,value);
            break;
        case TEMP:
            res = set_temp_shadow(&(inq->addr.id),inq->size,value);
            break;
        case FLAG:
            res = set_flags_shadow(inq->addr.id,value);
            break;
        default:
            assert(0);
            break;
    }
    return res;
}

static void hmap_print(gpointer key, gpointer value, gpointer func_p) {
    GFunc print_func = (GFunc)func_p;
    if(key!=NULL && value!=NULL){
        shadow_page *page = (shadow_page *)value;
        for(int i=0;i<PAGE_SIZE;i=i+SHD_SIZE_u64){
            if(page->bitmap[i]!=0){
                uint64_t addr = SHD_assemble_addr((uint64_t)key,(uint64_t)i);
                print_func((gpointer)&addr,(gpointer)&page->bitmap[i]);
            }
        }
    }
}

int SHD_list_mem(GFunc print_mem_shadows){
    int len = g_hash_table_size(SHD_Memory.pages);
    g_hash_table_foreach(SHD_Memory.pages,hmap_print, print_mem_shadows);
    return len;
}

int SHD_list_global(GFunc print_func){
    int len = 0;
    for(uint64_t i=0;i<GLOBAL_POOL_SIZE;i++){
        SHD_value *shadow = g_ptr_array_index(SHD_Memory.global_temps, i);
        if (*shadow!=0){
            len++;
            print_func((gpointer)&i,(gpointer)shadow);
        }
    }
    return len;
}

int SHD_list_temp(GFunc print_func){
    int len = 0;
    if (SHD_Memory.global_temps->len>GLOBAL_POOL_SIZE){
        for(uint64_t i=GLOBAL_POOL_SIZE;i<SHD_Memory.global_temps->len;i++){
            SHD_value *shadow = g_ptr_array_index(SHD_Memory.global_temps, i);
            if (*shadow!=0){
                len++;
                print_func((gpointer)&i,(gpointer)shadow);
            }
        }
    }
    return len;
}

shadow_err check_registers(uint64_t start, uint64_t end){
    for(uint64_t i=start;i<=end;i++){
        SHD_value *shadow = g_ptr_array_index(SHD_Memory.global_temps, i);
        if (*shadow!=0){
            return 2;
        }
    }
    return 0;
}