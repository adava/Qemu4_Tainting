//
// Created by sina on 4/20/2020.
//
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <stdint.h>
#include "../lib/shadow_memory.c"
#include "../lib/taint_propagation.c"

void MEM_read(uint64_t vaddr, int len, uint8_t *buf){
    if (len==1) {
        if (vaddr > 0xffff) {
            buf[0] = 0x70;
        } else {
            buf[0] = 0x7c;
        }
    }
}

void test_clear(){
    SHD_init();
    uint64_t u64_84 = 0x8004;
    uint16_t u16_1f=0x8fff;
    shad_inq inq3={.addr=u64_84,.type=MEMORY,.size=SHD_SIZE_u16};
    SHD_set_shadow(&inq3,&u16_1f);
    SHD_value after_set = SHD_get_shadow(inq3);
    SHD_clear(&inq3);
    SHD_value t1 = SHD_get_shadow(inq3);
    assert(t1==0);
    printf("SUCCESS testing SHD_clear: after setting=0x%llx, after clearing=0x%llx !\n",after_set,t1);
}
void test_copy() {
    SHD_init();
    uint64_t u64_e4 = 0xe004;
    uint64_t u64_01f=0x8fff;
    shad_inq inq1={.addr=u64_e4,.type=MEMORY,.size=SHD_SIZE_u64};
    SHD_set_shadow(&inq1,&u64_01f);
    SHD_value m1_after_set = SHD_get_shadow(inq1);

    int id_reg1 = 4;
    uint64_t u64_f5 = 0x10000fff5;
    shad_inq inq2={.addr=id_reg1,.type=GLOBAL,.size=SHD_SIZE_u64};
//    shad_inq inq2={.addr=id_reg1,.type=TEMP,.size=sizeof(uint64_t)}; //new id would be set!
    SHD_set_shadow(&inq2,&u64_f5);
    SHD_value r1_after_set = SHD_get_shadow(inq2);

    SHD_copy(inq2,&inq1);
    shad_inq inq3={.addr=u64_e4,.type=MEMORY,.size=SHD_SIZE_u64};
    SHD_value t1 = SHD_get_shadow(inq3);
    assert(t1==r1_after_set);
    printf("SUCCESS testing SHD_copy: after setting=0x%llx, after copying=0x%llx!\n",m1_after_set,t1);
}
void test_add_sub(){
    SHD_init();
    uint64_t u64_e4 = 0xe004;
    uint32_t u32_01e=0x8ffe;
    shad_inq inq1={.addr=u64_e4,.type=MEMORY,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq1,&u32_01e);
    SHD_value m1_after_set = SHD_get_shadow(inq1);

    int id_reg1 = 4;
    uint32_t u32_f4 = 0x1000fff4;
    shad_inq inq2={.addr=id_reg1,.type=GLOBAL,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq2,&u32_f4);
    SHD_add_sub(inq2,inq1,&inq1);
    SHD_value t1 = SHD_get_shadow(inq1);
    assert(t1==0xfffffffe);
    printf("SUCCESS testing SHD_add_sub: Add(0x%x, 0x%llx)=0x%llx!\n",u32_f4,m1_after_set,t1);
}
void test_union(){
    SHD_init();
    uint64_t u64_8e = 0x8ffe;
    uint32_t u32_01e=0xe004;
    shad_inq inq1={.addr=u64_8e,.type=MEMORY,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq1,&u32_01e);
    SHD_value m1_after_set = SHD_get_shadow(inq1);

    uint32_t u32_00 = 0x0ff0;
    shad_inq inq2={.addr=0,.type=TEMP,.size=SHD_SIZE_u32}; //new id would be set!
    SHD_set_shadow(&inq2,&u32_00);

    SHD_union(inq2,&inq1);
    SHD_value t1 = SHD_get_shadow(inq1);
    assert(t1==0xeff4);
    printf("SUCCESS testing SHD_union: Union(0x%x, 0x%llx)=0x%llx!\n",u32_00,m1_after_set,t1);
}
void test_extensionL(){
    SHD_init();
    uint64_t u64_8e = 0x8ffe;
    uint32_t u32_ef=0xe004;
    uint16_t u16_4=0x04;

    shad_inq inq1={.addr=u64_8e,.type=MEMORY,.size=SHD_SIZE_u32};
    shad_inq inq2={.addr=13,.type=GLOBAL,.size=SHD_SIZE_u16};
    SHD_set_shadow(&inq1,&u32_ef);
    SHD_set_shadow(&inq2,&u16_4);
    SHD_value m1_after_set = SHD_get_shadow(inq1);
    SHD_value r1_after_set = SHD_get_shadow(inq2);

    SHD_extensionL(inq1,&inq1);
    SHD_extensionL(inq2,&inq2);
    SHD_value t1 = SHD_get_shadow(inq1);
    SHD_value t2 = SHD_get_shadow(inq2);
    assert(t1==0xfffffffc);
    assert(t2==0xfffc);
    printf("SUCCESS testing SHD_extensionL: ExtensionL(0x%llx)=0x%llx, ExtensionL(0x%llx)=0x%llx!\n",m1_after_set,t1,r1_after_set,t2);
}

void test_exchange(){
    SHD_init();
    uint64_t u64_8e = 0x8ffe;
    uint32_t u32_01e=0xe004;
    shad_inq inq1={.addr=u64_8e,.type=MEMORY,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq1,&u32_01e);
    SHD_value m1_after_set = SHD_get_shadow(inq1);

    int id_reg1 = 1;
    uint32_t u32_f4 = 0x1000fff4;
    shad_inq inq2={.addr=id_reg1,.type=GLOBAL,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq2,&u32_f4);

    SHD_exchange(&inq1,&inq2);
    SHD_value t1 = SHD_get_shadow(inq1);
    SHD_value t2 = SHD_get_shadow(inq2);

    assert(t1==u32_f4);
    assert(t2==u32_01e);

    printf("SUCCESS testing SHD_exchange: 0x%llu = 0x%x -> 0x%llx, reg %d = 0x%x -> 0x%llx)!\n",inq1.addr.vaddr,u32_01e,t1,inq2.addr.id,u32_f4,t2);
}

void test_macro_and_or(){
    uint8_t op_v1 = 0x70;
    uint8_t shd1 = 0x4f;
    uint8_t op_v2 = 0x7c;
    uint8_t shd2 = 0x6a;
    uint8_t and_res = 0x6e;
    uint8_t or_res = 0x4b;
    uint8_t t1 = RULE_AND_OR(op_v1,shd1,op_v2,shd2,RULE_IMPROVE_AND);
    assert(t1==and_res);
    uint8_t t2 = RULE_AND_OR(op_v1,shd1,op_v2,shd2,RULE_IMPROVE_OR);
    assert(t2==or_res);
    printf("SUCCESS testing and_or macro: op1_v=0x%x, op2_v=0x%x, op1_shadow=0x%x, op1_shadow=0x%x, and_result=0x%x, or_result=0x%x\n",op_v1,op_v2,shd1,shd2,and_res,or_res);
}

void test_and(){
    SHD_init();
    uint8_t op_v1 = 0x70;
    uint8_t op_v2 = 0x7c;
    uint64_t u64_1e = 0x18ffe;
    uint8_t shd1 = 0x4f;
    shad_inq inq1={.addr=u64_1e,.type=MEMORY,.size=SHD_SIZE_u8};
    SHD_set_shadow(&inq1,&shd1);

    uint32_t u64_e4=0xe004;
    uint8_t shd2 = 0x6a;
    shad_inq inq2={.addr=u64_e4,.type=MEMORY,.size=SHD_SIZE_u8};
    SHD_set_shadow(&inq2,&shd2);
    SHD_and_or(inq1,&inq2, &op_v1, &op_v2, OP_AND);
    SHD_value t1 = SHD_get_shadow(inq2);
    uint8_t and_res = 0x6e;
    assert(t1==and_res);

    SHD_set_shadow(&inq2,&shd2);
    SHD_and_or(inq1,&inq2, &op_v1, &op_v2,OP_OR);
    SHD_value t2 = SHD_get_shadow(inq2);
    uint8_t or_res = 0x4b;
    assert(t2==or_res);

    uint8_t op1,op2=0;
    MEM_read(u64_1e,1,&op1);
    MEM_read(u64_e4,1,&op2);

    printf("SUCCESS testing SHD_and_or: AND/OR(op1_v=0x%x, op1_shadow=0x%x, op2_v=0x%x, op2_shadow=0x%x)=0x%llx/0x%llx!\n",op1,shd1,op2,shd2,t1,t2);
    //uint8_t or_res = 0x4b;
}

void test_op_rotate(){
    uint64_t d1 = 0x10000fff5;
    uint64_t rotate_size1 = 32;
    uint64_t v = rotate_op(d1,rotate_size1,Rol);
    assert(0xfff500000001==v);
    printf("SUCCESS testing ROL(0x%llx,0x%llu)=0x%llx\n",d1,rotate_size1,v);
    uint64_t rotate_size2 = 8;
    uint64_t d2 = 0xfff5;
    uint64_t t = rotate_op(d2,rotate_size2,Ror);
    assert(0xf5000000000000ff==t);
    printf("SUCCESS testing ROR(0x%llx,0x%llu)=0x%llx\n",d2,rotate_size2,t);
}

void test_cast(){
    uint16_t d1 = 0xfff5;
    SHD_value v1 =0 ;
    SHD_cast(&d1,SHD_SIZE_u16,&v1,SHD_SIZE_u32);
    printf("SUCCESS testing cast(0x%x)=0x%llx\n",d1,v1);
}

void test_Shift_Rotation(){
    SHD_init();
    uint64_t d1 = 0x10000fff5;
    uint16_t rotate_size1 = 32;
    uint64_t u64_1e = 0x18ffe;
    uint16_t rotate_shd = 0xff00;

    shad_inq inq1={.addr=u64_1e,.type=MEMORY,.size=SHD_SIZE_u64};
    SHD_set_shadow(&inq1,&d1);

    shad_inq inq2={.addr=rotate_size1,.type=IMMEDIATE,.size=SHD_SIZE_u16};

    SHD_Shift_Rotation(inq2,&inq1,Rol);
    SHD_value t1 = SHD_get_shadow(inq1);
    assert(t1==0xfff500000001);
    shad_inq inq3={.addr=3,.type=GLOBAL,.size=SHD_SIZE_u16};
    SHD_set_shadow(&inq3,&rotate_shd);
    SHD_Shift_Rotation(inq3,&inq1,Rol);//not analyzed
    SHD_value t2 = SHD_get_shadow(inq1);
    printf("SUCCESS testing SHD_Shift_Rotation Rol(0x%llx,imm/tainted_reg=0x%u)=0x%llx\t0x%llx\n",d1,rotate_size1,t1,t2);
}

void test_copy_conservative(){
    SHD_init();
    uint32_t d1 = 0x100005;
    uint64_t u64_1e = 0x18ffe;
    shad_inq inq1={.addr=u64_1e,.type=MEMORY,.size=SHD_SIZE_u32};
    SHD_set_shadow(&inq1,&d1);

    int flag_id = 0;
    shad_inq inq2 = {.addr.id=flag_id,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(inq1,&inq2);
    SHD_value t1 = SHD_get_shadow(inq2);
    assert(t1=0xff);

    shad_inq inq3={.addr=3,.type=GLOBAL,.size=SHD_SIZE_u64};
    SHD_copy_conservative(inq1,&inq3);
    SHD_value t2 = SHD_get_shadow(inq3);
    assert(t2=-1);

    printf("SUCCESS testing SHD_copy_conservative: copying 0x%x to flag %d =>0x%llx, and to register %d =>0x%llx\n",d1,flag_id,t1,inq3.addr.id,t2);
}

void test_write_contiguous() {
    SHD_init();
    uint64_t u64_84 = 0x8004;
    uint8_t u8_f = 0xff;
    uint32_t size = 0x1fe4;
    shadow_err er2 = SHD_write_contiguous(u64_84, size, u8_f);
    assert(er2 == 0);

    shad_inq inq1 = {.addr.vaddr=0x900e, .type=MEMORY, .size=SHD_SIZE_u64};
    SHD_value sh1 = SHD_get_shadow(inq1);

    shad_inq inq2 = {.addr.vaddr=0x800e, .type=MEMORY, .size=SHD_SIZE_u64};
    SHD_value sh2 = SHD_get_shadow(inq2);

    shad_inq inq3 = {.addr.vaddr=0xa00e, .type=MEMORY, .size=SHD_SIZE_u64};
    SHD_value sh3 = SHD_get_shadow(inq3);
    printf("SUCCESS testing SHD_write_contiguous, writing %d bytes to 0x%llx: vaddr=0x%llx -> value=0x%llx\tvaddr=0x%llx -> value=0x%llx\tvaddr=0x%llx -> value=0x%llx\n",
           size, u64_84, inq1.addr.vaddr, sh1, inq2.addr.vaddr, sh2, inq3.addr.vaddr, sh3);
}

void test_test(){
    SHD_init();
    uint8_t op_v1 = 0x70;
    uint8_t op_v2 = 0x7c;
    uint64_t u64_1e = 0x18ffe;
    uint8_t shd1 = 0x4f;
    shad_inq inq1={.addr=u64_1e,.type=MEMORY,.size=SHD_SIZE_u8};
    SHD_set_shadow(&inq1,&shd1);

    uint32_t u64_e4=0xe004;
    uint8_t shd2 = 0x6a;
    shad_inq inq2={.addr=u64_e4,.type=MEMORY,.size=SHD_SIZE_u8};
    SHD_set_shadow(&inq2,&shd2);

    shad_inq flag1={.addr=0,.type=FLAG,.size=SHD_SIZE_u8};
    shadow_err res=SHD_test(inq1,inq2,flag1,&op_v1,&op_v2);

    SHD_value t1 = SHD_get_shadow(flag1);
    uint8_t test_res = 0xff;
    assert(t1==test_res);

    SHD_value t2 = SHD_get_shadow(inq2);
    assert(t2==0x6a);

    printf("SUCCESS testing SHD_test: AND/OR(op1_v=0x%x, op1_shadow=0x%x, op2_v=0x%x, op2_shadow=0x%x)=0x%llx/0x%llx!\n",op_v1,shd1,op_v2,shd2,t1,t2);
}

int main() {
    test_clear();
    test_copy();
    test_add_sub();
    test_union();
    test_extensionL();
    test_exchange();
    test_macro_and_or();
    test_and();
    test_op_rotate();
    test_cast();
    test_Shift_Rotation();
    test_copy_conservative();
    test_write_contiguous();
    test_test();
    return 0;
}
