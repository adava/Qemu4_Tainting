//
// Created by sina on 4/16/2020.
//

void test_conversion(){
    uint8_t u8_127 = 127;
    uint64_t u64_127 = convert_value(&u8_127,1);
    uint8_t u8_255 = 255;
    uint64_t u64_255 = convert_value(&u8_255,1);
    uint16_t u16_1h = 0x8000;
    uint64_t u64_1h = convert_value(&u16_1h,2);
    uint16_t u16_f = 0xffff;
    uint64_t u64_f = convert_value(&u16_f,2);
    printf("u64_127=%llu, u64_255=%llu,u64_1h=%llu, u64_f=%llu\n",u64_127,u64_255,u64_1h,u64_f);
}

void test_global_get_set(){
    SHD_init();
    uint16_t u16_f = 0xffff;
    set_global_shadow(5,2,&u16_f);

    SHD_value *shd1 = get_shadow_global(1);
    SHD_value *shd2 = get_shadow_global(5);
    printf("shd1=%llu, shd2=%llu\n",*shd1,*shd2);
    SHD_value *shd3 = get_shadow_global(126);
}

void test_offsets(){
    SHD_value shd2 = 0xffff;
    SHD_value of1=SHD_find_offset(shd2);
    SHD_value p1=SHD_find_page_addr(shd2);
    printf("of1=%llu, p1=%llu\ns, shd2=%llu\n",of1,p1,shd2);
}

void test_sh_mem(){
    SHD_init();
    uint64_t u64_f1 = 0xfff1;
    uint64_t u64_f5 = 0x10000fff5;
    SHD_value of1=SHD_find_offset(u64_f1);
    SHD_value p1=SHD_find_page_addr(u64_f1);
    printf("of1=%llu, p1=%llu\nu64_f1=%llu, mask=0x%x\n",of1,p1,u64_f1,PAGE_MASK);

    uint16_t u16_1f=0x8fff;
    uint32_t u32_6=0x6;
    set_memory_shadow(u64_f1, sizeof(u16_1f),&u16_1f);
    set_memory_shadow(u64_f5, sizeof(u32_6),&u32_6);

    assert(find_shadow_page(u64_f1)==find_shadow_page(u64_f5));

    void *sh_mem = get_shadow_memory(u64_f1);
    assert(sh_mem!=NULL);
    uint16_t sh_value = *((uint16_t*)sh_mem);
    assert(sh_value==u16_1f);

    void *sh_mem2 = get_shadow_memory(u64_f5);
    assert(sh_mem2!=NULL);
    uint32_t sh_value2 = *((uint32_t*)sh_mem2);
    assert(sh_value2==u32_6);

    printf("sh_value=%u, sh_value2=%u\nfinished!\n",sh_value,sh_value2);
}

void test_sh_temp(){
    SHD_init();
    uint64_t u64_f1 = 0xfff1;
    uint64_t u64_f5 = 0x10000fff5;

    int id1=0;
    int id2=0;
    set_temp_shadow(&id1, sizeof(uint64_t), &u64_f1);
    assert(id1==GLOBAL_POOL_SIZE);
    set_temp_shadow(&id2, sizeof(uint64_t), &u64_f5);
    assert(id2==GLOBAL_POOL_SIZE+1);
    SHD_value g_sh1=*get_shadow_global(id1);
    assert(g_sh1==u64_f1);
    SHD_value g_sh2=*get_shadow_global(id2);
    assert(g_sh2==u64_f5);
    printf("id1=%d, id2=%d, sh1=%llu, sh2=%llu\n",id1,id2,g_sh1,g_sh2);
}

void test_SHD_get_set(){
    SHD_init();
    uint64_t u64_f1 = 0xfff1;
    uint64_t u64_f5 = 0x10000fff5;
    int id1=0;
    int id2=12;
    shad_inq inq1={.addr=id1,.type=TEMP,.size=sizeof(uint64_t)};
    shad_inq inq2={.addr=id2,.type=GLOBAL,.size=sizeof(u64_f5)};
    SHD_set_shadow(&inq1,&u64_f1);
    SHD_set_shadow(&inq2,&u64_f5);

    uint64_t u64_84 = 0x8004;
    uint16_t u16_1f=0x8fff;
    shad_inq inq3={.addr=u64_84,.type=MEMORY,.size=sizeof(uint16_t)};
    SHD_set_shadow(&inq3,&u16_1f);

    SHD_value g_sh1=SHD_get_shadow(inq1);
    assert(g_sh1==u64_f1);
    SHD_value g_sh2=SHD_get_shadow(inq2);
    assert(g_sh2==u64_f5);
    SHD_value sh_value=SHD_get_shadow(inq3);
    assert(sh_value==u16_1f);
    printf("id1=%d, id2=%d, sh1=%llu, sh2=%llu, vaddr=%llu, vaddr_shd=%x\n",inq1.addr.id,inq2.addr.id,g_sh1,g_sh2,u64_84,u16_1f);
}