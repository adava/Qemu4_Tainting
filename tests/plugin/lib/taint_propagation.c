//
// Created by sina on 4/20/2020.
//
//#include <stdint.h>
#include <limits.h>
#include "shadow_memory.h"
#include "taint_propagation.h"

uint64_t rotate_op(uint64_t n, uint64_t c, shift_op op);

SHD_value and_or(shad_inq src, shad_inq *dst, uint8_t *src_val, uint8_t *dst_val, logical_op op);

uint64_t rotate_op(uint64_t n, uint64_t c, shift_op op){
    const uint64_t mask = MASK(n);
    c = DO_MASK(c,mask);
    uint64_t res = 0;
    switch (op){
        case Rol:
            res = (n<<c) | (n>> DO_MASK(-c,mask));
            break;
        case Ror:
            res = (n>>c) | (n<< DO_MASK(-c,mask));
            break;
        default:
            assert(0);
    }
    return res;
}

shadow_err SHD_clear(shad_inq *src){
    SHD_value zero = 0;
    SHD_set_shadow(src,&zero);
    return 0;
}

shadow_err SHD_copy(shad_inq src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(src);
    shadow_err r = SHD_set_shadow(dst,&s_val);
    return r;
}

shadow_err SHD_cast(void *src,SHD_SIZE old_size,void *res, SHD_SIZE new_size){ //this is different than convert_value
    uint8_t buf[SHD_SIZE_MAX]={0};
    uint64_t s_v = convert_value(src,old_size);
    switch (new_size){
        case SHD_SIZE_u8:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint8_t));
            *(uint8_t*)res = DEREF_TYPE(buf,uint8_t);
            break;
        case SHD_SIZE_u16:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint16_t));
            *(uint16_t*)res = DEREF_TYPE(buf,uint16_t);
            break;
        case SHD_SIZE_u32:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint32_t));
            *(uint32_t*)res = DEREF_TYPE(buf,uint32_t);
            break;
        case SHD_SIZE_u64:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint64_t));
            *(uint64_t*)res = DEREF_TYPE(buf,uint64_t);
            break;
        default:
            assert(0);
    }
//    printf("cast(): old_value=%llx, new_val=%llx\n",s_v,*res);
    return 0;
}

shadow_err SHD_union(shad_inq src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(src);
    SHD_value d_val = SHD_get_shadow(*dst);
    SHD_value res = RULE_UNION(s_val,d_val);
    shadow_err r = SHD_set_shadow(dst,&res);
    return r;
}

shadow_err SHD_add_sub(shad_inq src1, shad_inq src2, shad_inq *sd){
    SHD_value s_val = SHD_get_shadow(src1);
    SHD_value d_val = SHD_get_shadow(src2);
    SHD_value res = RULE_LEFT(RULE_UNION(s_val,d_val));
    shadow_err r = SHD_set_shadow(sd,&res);
    return r;
}
shadow_err SHD_CAddSub(shad_inq src1, shad_inq src2, shad_inq carry,shad_inq *sd){
    SHD_value s1_val = src1.type==IMMEDIATE?0:SHD_get_shadow(src1);
    SHD_value s2_val = SHD_get_shadow(src2);
    SHD_value c_val = SHD_get_shadow(carry);
    SHD_value casted_C = 0;
    int m_size = src1.size>=src2.size?src1.size:src2.size;
    SHD_cast(&c_val,sizeof(SHD_value),&casted_C, m_size);
    SHD_value res = RULE_UNION(RULE_LEFT(RULE_UNION(s1_val,s2_val)),casted_C);
    shadow_err r = SHD_set_shadow(sd,&res); //size is not considered
    return r;
}

shadow_err SHD_LEA(shad_inq src1, shad_inq src2, int shift_val, shad_inq *sd){
    SHD_value d_val = 0;
    SHD_value s_val = 0;
    if(src1.type!=IMMEDIATE && src1.addr.vaddr!=0){
        s_val = SHD_get_shadow(src1);
        if (shift_val!=0){
            s_val = s_val << shift_val;
        }
    }
    if(src2.type!=IMMEDIATE && src2.addr.vaddr!=0){
        d_val = SHD_get_shadow(src2);
    }
    SHD_value res = RULE_LEFT(RULE_UNION(s_val,d_val));
    shadow_err r = SHD_set_shadow(sd,&res); //update the sd regardless, because we don't know what it was before
    return r;
}

shadow_err SHD_extensionL(shad_inq src, shad_inq *dst){ //would consider the destination length! NOT TESTED!
    SHD_value s_val = SHD_get_shadow(src);
    SHD_value res = RULE_LEFT(s_val);
    uint8_t buf[SHD_SIZE_MAX]={0};
    shadow_err r=0;
    switch(dst->size){
        case SHD_SIZE_u8:
            DEREF_TYPE(buf,uint8_t)=res&0xff;
            break;
        case SHD_SIZE_u16:
            DEREF_TYPE(buf,uint16_t)=res&0xffff;
            break;
        case SHD_SIZE_u32:
            DEREF_TYPE(buf,uint32_t)=res&0xffffffff;
            break;
        case SHD_SIZE_u64:
            DEREF_TYPE(buf,uint64_t)=res;
            break;
        default:
            assert(0);
    }
    r = SHD_set_shadow(dst,buf);
    return r;
}

shadow_err SHD_CMP(shad_inq src, shad_inq dst, shad_inq flag){
    shad_inq *im_op = NULL;
    SHD_value res = 0;
    SHD_value s_val, d_val;
    uint8_t value[SHD_SIZE_MAX] = {0};
    shadow_err r=0;
    if(src.type==IMMEDIATE && dst.type!=IMMEDIATE){
        im_op = &dst;
    }else if (dst.type == IMMEDIATE && src.type!=IMMEDIATE){
        im_op = &src;
    }else if (dst.type == IMMEDIATE && src.type==IMMEDIATE){
        r = 2;
        return r;
    }
    if(im_op!=NULL){
        s_val = SHD_get_shadow(*im_op);
        res = RULE_LEFT(s_val);
    }
    else{
        s_val = SHD_get_shadow(src);
        d_val = SHD_get_shadow(dst);
        res = RULE_LEFT(RULE_UNION(s_val,d_val));
    }
    SHD_cast(&res, sizeof(SHD_value),value, flag.size);
    r = SHD_set_shadow(&flag,&value);
    return r;
}

shadow_err SHD_exchange(shad_inq *src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(*src);
    SHD_value d_val = SHD_get_shadow(*dst);
    shadow_err r1 = SHD_set_shadow(dst,&s_val);
    shadow_err r2 = SHD_set_shadow(src,&d_val);
    return r1 | r2;
}

SHD_value and_or(shad_inq src, shad_inq *dst, uint8_t *src_val, uint8_t *dst_val, logical_op op){
    SHD_value sh_src, sh_dst;
    uint64_t op1_v, op2_v;
    if(src.type==IMMEDIATE){
        sh_src = 0;
        op1_v = src.addr.vaddr;
    }
    else{
        op1_v = convert_value(src_val,src.size);
        sh_src = SHD_get_shadow(src);
    }
    if(dst->type==IMMEDIATE){
        sh_dst = 0;
        op2_v = dst->addr.vaddr;
    }
    else{
        op2_v = convert_value(dst_val,dst->size);
        sh_dst = SHD_get_shadow(*dst);
    }
    SHD_value res = 0;
    switch (op){
        case OP_AND:
            res = RULE_AND_OR(op1_v, sh_src, op2_v, sh_dst, RULE_IMPROVE_AND);
            break;
        case OP_OR:
            res = RULE_AND_OR(op1_v, sh_src, op2_v, sh_dst, RULE_IMPROVE_OR);
            break;
        default:
            printf("OP_AND=%d, OP_AND=%d, op=%d\n",OP_AND,OP_OR,op);
            assert(0);
    }
    return res;
}

shadow_err SHD_and_or(shad_inq src, shad_inq *dst, uint8_t *src_val, uint8_t *dst_val, logical_op op){
    SHD_value res = and_or(src, dst, src_val, dst_val, op);
    shadow_err r = SHD_set_shadow(dst,&res);
    return r;
}

shadow_err SHD_test(shad_inq src1, shad_inq src2, shad_inq flag ,uint8_t *src_val, uint8_t *dst_val){
    SHD_value res = and_or(src1, &src2, src_val, dst_val, OP_AND);
    uint8_t value[SHD_SIZE_MAX] = {0};
    SHD_cast(&res, sizeof(SHD_value),value, flag.size);
    shadow_err r = SHD_set_shadow(&flag,&value);
    return r;
}

shadow_err SHD_Shift_Rotation(shad_inq src, shad_inq *dst, shift_op op){
    SHD_value d_val, s_val, shift_res;
    d_val = SHD_get_shadow(*dst);
    s_val = 0;
    if (src.type!=IMMEDIATE){
        SHD_value temp1= SHD_get_shadow(src);
        SHD_cast(&temp1,src.size,&s_val,dst->size);
    }
    switch (op){
        case Shl:
            shift_res = d_val << src.addr.vaddr;
            break;
        case Shr:
        case Sar:
            shift_res = d_val >> src.addr.vaddr;
            break;
//        case Sal: //not included in memcheck shift rules
//            shift_res = d_val << src.addr.vaddr;
//            break;
        case Ror:
        case Rol:
            shift_res = rotate_op(d_val,src.addr.vaddr,op);
            break;
        default:
            assert(0);
    }
    d_val = RULE_UNION(s_val,shift_res);
    SHD_set_shadow(dst,&d_val);
    return 0;
}

shadow_err SHD_copy_conservative(shad_inq src, shad_inq *dst){
    SHD_value dst_shadow= SHD_get_shadow(src);
    uint8_t value[SHD_SIZE_MAX] = {0};
    SHD_cast(&dst_shadow, sizeof(SHD_value),value, dst->size);
    shadow_err r = SHD_set_shadow(dst,&value);
    return r;
}

shadow_err SHD_write_contiguous(uint64_t vaddr, uint32_t size, uint8_t value){
    uint64_t page_id = (vaddr & ~OFFSET_MASK);
    //printf("page_id=%lx\n",page_id);
    uint64_t new_addr = vaddr;
    uint32_t written_bytes = 0;
    while(vaddr + size > page_id + PAGE_SIZE){
        uint32_t new_size = (page_id + PAGE_SIZE - new_addr);
        shadow_err res = write_memory_shadow(new_addr,new_size,value);
        if (res!=0){
            return res;
        }
        written_bytes+=new_size;
        new_addr = new_addr + new_size;
        page_id = (new_addr & ~OFFSET_MASK);
    }
    if (written_bytes!=size){
        return write_memory_shadow(written_bytes+vaddr,size-written_bytes,value);
    }
    return 0;
}