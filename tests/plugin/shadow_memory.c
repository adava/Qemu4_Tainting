//
// Created by sina on 4/15/20.
//
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "shadow_memory.h"

shadow_page *find_shadow_page(uint64_t vaddr); // would get the higher part of the address and searches SHD_Memory pages for the inquiry page

void *get_shadow_memory(uint64_t vaddr); //the entire memory is addressable, plus this is an internal function. The caller fetches properly

SHD_value *get_shadow_global(int id); //would return temps as well, the storage is in sizeof(SHD_value) so the caller must fetch the correct chunk

shadow_err set_memory_shadow(uint64_t vaddr, uint8_t size, void *value);

shadow_err set_global_shadow(int id, uint8_t size, void *value);

shadow_err set_temp_shadow(int *id, uint8_t size, void *value); //would return the inserted id

uint64_t convert_value(void *value, uint8_t size);

guint SHD_ghash_addr(gconstpointer key){
    uint64_t h = (uint64_t)key;
    h = SHD_find_page_addr(h);
    return ((guint)h);
}

uint64_t convert_value(void *value, uint8_t size){
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
            printf("unknown size for conversion!");
            exit(1);
            break;
    }
    return temp;
}

void SHD_initialize_globals(){
    for(int i=0;i<GLOBAL_POOL_SIZE;i++){
        SHD_value *shadow = g_new0(SHD_value,1); //would initialize to zero
        g_ptr_array_add(SHD_Memory.global_temps,shadow);
    }
}

void SHD_init(){
    SHD_Memory.pages = g_hash_table_new_full(SHD_ghash_addr, g_direct_equal, NULL, NULL);
    SHD_Memory.global_temps = g_ptr_array_new_full(GLOBAL_POOL_SIZE,NULL);
    SHD_initialize_globals();
}

shadow_page *find_shadow_page(uint64_t vaddr){
    shadow_page *page = g_hash_table_lookup (SHD_Memory.pages,SHD_KEY_CONVERSION(vaddr));
    return page;
}

SHD_value *get_shadow_global(int id){
    SHD_value *shadow = g_ptr_array_index(SHD_Memory.global_temps, id);
    //could return NULL
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

SHD_value SHD_get_shadow(shad_inq inq){
    void *shv;
    SHD_value rval=0;
    switch (inq.type){
        case MEMORY:
            shv = get_shadow_memory(inq.addr.vaddr);
            break;
        case GLOBAL:
        case TEMP:
            shv = get_shadow_global(inq.addr.id);
            break;
        default:
            assert(0);
    }
    if (shv!=NULL){
        if(inq.type==MEMORY){
            rval = convert_value(shv,inq.size);
        }
        else{
            rval = *((SHD_value*)shv);//unlike memory, globals are stored in SHD_value chunks
        }
    }
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

shadow_err set_global_shadow(int id, uint8_t size, void *value){
    assert(id<GLOBAL_POOL_SIZE);
    SHD_value *shadow = get_shadow_global(id); //get the reference
    assert(shadow!=NULL);
    *shadow = convert_value(value, size); //assignment
    return 0;
}

shadow_err set_memory_shadow(uint64_t vaddr, uint8_t size, void *value){
    shadow_page *page = find_shadow_page(vaddr);
    if (page==NULL){
        page = g_new0(shadow_page,1);
        g_hash_table_insert (SHD_Memory.pages,(gpointer)(vaddr),page);
    }
    memcpy(&(page->bitmap[SHD_find_offset(vaddr)]),value,size);
    return 0;
}
shadow_err SHD_set_shadow(shad_inq *inq, void *value){
    shadow_err res=0;
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
        default:
            assert(0);
            break;
    }
    return res;
}
//#include "shadow_aux_tests.c"
//int main(){
//    test_SHD_get_set();
//    return 0;
//}