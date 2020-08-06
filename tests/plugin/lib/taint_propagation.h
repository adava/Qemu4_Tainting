//
// Created by sina on 4/20/2020.
//
#include "shadow_memory.h"

#ifndef TAINT_PROPAGATION_H
#define TAINT_PROPAGATION_H

#define MASK(n) ((CHAR_BIT*sizeof(n))-1)
#define DO_MASK(c,mask) (c & mask)

#define ROTATE_LEFT(n, c) asm inline ("rol %1, %0\n\t" : "=r" (n) : "=r" (c)) //not tested

#define RULE_PES_APPLY(s_v,x) s_v==0?(x=0):(x=0-1)
#define RULE_LEFT(a) ((0-a)|a) //(0-a) is the two's complement or the negation
#define RULE_UNION(a,b) (a|b)
#define RULE_INTERSECT(a,b) (a&b)
#define RULE_IMPROVE_AND(a,b) RULE_UNION(a,b)
#define RULE_IMPROVE_OR(a,b) RULE_UNION(~a,b) //a is the Value, and be is the shadow!
#define RULE_AND_OR(op1_v, sh_src, op2_v, sh_dst, improve_op) RULE_INTERSECT(RULE_UNION(sh_src, sh_dst),RULE_INTERSECT(improve_op(op1_v, sh_src), improve_op(op2_v, sh_dst)))
typedef enum{
    Shl,
    Shr,
    Sar,
    Sal,
    Rol,
    Ror,
    OP_AND,
    OP_OR,
    COND_JMP
} instruction_operation;

typedef instruction_operation shift_op;
typedef instruction_operation logical_op;

typedef void (*guest_memory_read_func)(uint64_t vaddr, int len, uint8_t *buf);

shadow_err SHD_clear(shad_inq *src);

shadow_err SHD_copy(shad_inq src, shad_inq *dst); //Mov r/m,r/m dst.id would be set in callee for temps. src would be zero extended.

shadow_err SHD_write_contiguous(uint64_t vaddr, uint32_t size, uint8_t value); //This is for input reads, where a large chunk of taint sources would be tainted. This API takes care of size spanning multiple pages.

shadow_err SHD_cast(void *src,SHD_SIZE old_size,void *res, SHD_SIZE new_size); // pessimistic cast (widens to the new size)

shadow_err SHD_add_sub(shad_inq src1, shad_inq src2, shad_inq *sd); // Internally it is a union and an extendL

shadow_err SHD_CAddSub(shad_inq src1, shad_inq src2, shad_inq carry,shad_inq *sd);

shadow_err SHD_LEA(shad_inq src1, shad_inq src2, int shift_val, shad_inq *sd);

shadow_err SHD_union(shad_inq src, shad_inq *dst); // XOR

shadow_err SHD_extensionL(shad_inq src, shad_inq *dst); //Inc, Dec, LEA when one op is constant

shadow_err SHD_CMP(shad_inq src, shad_inq dst, shad_inq flag);

shadow_err SHD_exchange(shad_inq *src, shad_inq *dst); //XCHG and BSWAP

shadow_err SHD_and_or(shad_inq src, shad_inq *dst, uint8_t *src_val, uint8_t *dst_val, logical_op op); // A custom rule that needs runtime operand values

shadow_err SHD_test(shad_inq src1, shad_inq src2, shad_inq flag ,uint8_t *src_val, uint8_t *dst_val);

shadow_err SHD_Shift_Rotation(shad_inq src,shad_inq *dst, shift_op op); //handles all these operations in one function since the workflow is the same

shadow_err SHD_copy_conservative(shad_inq src, shad_inq *dst);

//shadow_err SHD_set_eflags(shad_inq src, shad_inq *dst); use SHD_copy_conservative with flags id
//shadow_err SHD_clear_eflags(shad_inq flgs); use SHD_clear
//shadow_err SHD_mul(shad_inq dst, shad_inq src1, shad_inq src2);  For now, use SHD_copy_conservative.

//shadow_err SHD_clear_extensionL(shad_inq src, shad_inq dst); //maybe useful for LEA

#endif //TAINT_PROPAGATION_H