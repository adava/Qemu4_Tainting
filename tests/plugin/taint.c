/*
 * Copyright (C) 2019, Alex Bennée <alex.bennee@linaro.org>
 *
 * How vectorised is this code?
 *
 * Attempt to measure the amount of vectorisation that has been done
 * on some code by counting classes of instruction.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>
#include <capstone.h>
#include <stdint.h>
//#include "lib/shadow_memory.h"
#include "lib/tainting.c"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define ALLOC_SET0(ptr,type) ptr = malloc(sizeof(type)); \
                             memset(ptr,0,sizeof(type));

#define PLUGIN_OPT

typedef enum {
    COUNT_CLASS,
    COUNT_INDIVIDUAL,
    COUNT_NONE
} CountType;
//static bool plugin_optimize=true;

static bool do_inline;
static bool verbose;
GHashTable *unsupported_ins_log;
GHashTable *syscall_rets;

static inline void analyzeOp(shad_inq *inq, cs_x86_op operand){
    switch(operand.type){
        case X86_OP_REG:
            inq->type = GLOBAL;
            inq->addr.id = MAP_X86_REGISTER(operand.reg);
            break;
        case X86_OP_IMM:
            inq->type = IMMEDIATE;
            inq->addr.vaddr = operand.imm;
            break;
        case X86_OP_MEM:
            inq->type = MEMORY;
            break;
        default:
            printf("unsupported operand type=%d\n",operand.type);
            assert(0);
    }
    if(inq->addr.vaddr>=GLOBAL_POOL_SIZE && inq->type==GLOBAL){
        printf("operand.reg=%x name=%s, mapped_val=%x\n",operand.reg,get_reg_name(operand.reg),inq->addr.id);
        assert(0);
    }
    inq->size = operand.size<SHD_SIZE_MAX?operand.size:SHD_SIZE_u64;
}

static inline qemu_plugin_vcpu_udata_cb_t analyze_LEA_Addr(inst_callback_argument *res, x86_op_mem *mem_op){ //assumes segment would not be tainted
    if (mem_op->index==X86_REG_INVALID && mem_op->base==X86_REG_INVALID){
        res->src.type = IMMEDIATE; //deactivate memory callback
        return taint_cb_clear;
    }
    if (mem_op->index!=X86_REG_INVALID){
        res->src.addr.id = MAP_X86_REGISTER(mem_op->index);
        res->src.size = regsize_map_64[mem_op->index];
        res->src.type = GLOBAL;

    }else{
        res->src.type = IMMEDIATE;
    }
    if (mem_op->base!=X86_REG_INVALID){
        res->src2.addr.id = MAP_X86_REGISTER(mem_op->base);
        res->src2.size = regsize_map_64[mem_op->base];
        res->src2.type = GLOBAL;
    }else{
        res->src2.type = IMMEDIATE;
    }
    if (mem_op->scale!=1){
        res->src3.addr.vaddr = mem_op->scale;
        res->src3.type = IMMEDIATE;
        res->src3.size = SHD_SIZE_u32;
    }
    return taint_cb_LEA;
}

static inline inst_callback_argument *analyze_Operands(cs_x86_op *operands,int numOps){
    inst_callback_argument *res = malloc(sizeof(inst_callback_argument));
    memset(res,0,sizeof(inst_callback_argument));
    switch(numOps){
        case 0:
            free(res);
            res = NULL;
            break;
        case 1:
            analyzeOp(&res->src, operands[0]);;
            break;
        case 2:
            analyzeOp(&res->src, operands[0]);
            analyzeOp(&res->dst, operands[1]);
            break;
        case 3:
            analyzeOp(&res->src, operands[0]);
            analyzeOp(&res->src2, operands[1]);
            analyzeOp(&res->dst, operands[2]);
            break;
        default:
            printf("WARNING: more than three operands=%d\n",numOps);
            break;
    }
    return res;
}

static void op_mem(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
                     uint64_t vaddr, void *udata)
{
    mem_callback_argument *arg;
    if (udata!=NULL){
        arg = (mem_callback_argument *)udata;
        *(arg->addr) = vaddr;
#ifdef CONFIG_2nd_CCACHE
        shad_inq inq = {.addr.vaddr=vaddr,.type=MEMORY,.size=SHD_SIZE_u64};
        SHD_value shd=SHD_get_shadow(inq);
        if(shd && second_ccache_flag==CHECK){
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
            printf("switching in op_mem\n");
#endif
            switch_mode(TRACK, true, arg->ip);
        }
#endif
        if (arg->args!=NULL && arg->callback!=NULL){
            arg->callback(cpu_index, (void *)arg->args);
        }
    }
    else{
        assert(0);
    }
    DEBUG_MEMCB_OUTPUT(arg->addr);
}

static void op_record_values(unsigned int cpu_index, void *udata) {
    INIT_ARG(arg,udata);
    READ_VALUE(arg->src,&arg->vals->src_val);
    READ_VALUE(arg->src2,&arg->vals->src2_val);
    READ_VALUE(arg->dst,&arg->vals->dst_val);
//    g_autofree gchar *report = g_strdup_printf("in op_record_values!\n");
//    qemu_plugin_outs(report);
}


//static void free_record(gpointer data)
//{
//    shadow_page *rec = (shadow_page *) data;
//    g_free(rec->bitmap);
//    g_free(rec);
//}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autofree gchar *report = g_strdup_printf("\nDEBUG output end:\n");
    qemu_plugin_outs(report);

    taint_list_all();

    g_autoptr(GString) end_rep = g_string_new("\n");
    print_unsupported_ins(end_rep,unsupported_ins_log);
    g_string_append_printf(end_rep, "Done\n");
    qemu_plugin_outs(end_rep->str);
}

static void plugin_init(void)
{
    g_autoptr(GString) report = g_string_new("Initialization:\n");
#ifdef CONFIG_2nd_CCACHE
    printf("2nd code cache optimization is activated!\n");
#endif
#ifndef CONFIG_DEBUG_CCACHE_SWITCH
    printf("debugging information for 2nd code cache optimization would not be printed!\n");
#endif
    unsupported_ins_log =  g_hash_table_new_full(NULL, g_direct_equal, NULL, NULL);
    syscall_rets =  g_hash_table_new_full(NULL, g_direct_equal, NULL, NULL);
    init_register_mapping();
    SHD_init();
#ifdef CONFIG_2nd_CCACHE
    second_ccache_flag = CHECK;
#endif
    g_string_append_printf(report,"Done!\n");
    qemu_plugin_outs(report->str);

}

static void syscall_callback(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8)
{
    g_autoptr(GString) out = g_string_new("******system call*******");
    g_string_append_printf(out,"\tnum: %"PRIu64"\n", num);
    // For read system call, num==0, a2 holds the buffer address (to which the read bytes are written) and a3 holds the buff size.
    if(num==0 && a1==0){ //only standard in; a1==0
//        uint8_t value = 0xff;
//        SHD_write_contiguous(a2, a3,value);

        uint64_t *vaddr = g_new0(uint64_t,1);
        *vaddr = a2;
        g_hash_table_insert(syscall_rets,(gpointer)(num),vaddr);
        g_string_append_printf(out,"TAINTED SOURCE\t I/O descriptor: %" PRIu64" , source addr: 0x%lx , buf size: %" PRIu64 "\n",
                a1,a2,a3);
        if(!DEBUG_SYSCALL){
            qemu_plugin_outs(out->str);
        }
    }
    if(DEBUG_SYSCALL){
        qemu_plugin_outs(out->str);
    }
}


static void syscall_ret_callback(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, int64_t ret){
    if(num==0){
        g_autoptr(GString) out = g_string_new("******system call return *******");
        g_string_append_printf(out,"\tTainting syscall num: %"PRIu64, num);
        uint64_t *addr = g_hash_table_lookup(syscall_rets, (gpointer)num);
        if(addr!=NULL){
            uint8_t value = 0xff;
            SHD_write_contiguous(*addr, ret, value);
            int removed = g_hash_table_remove(syscall_rets, (gpointer)num);
            g_assert(removed);
            g_string_append_printf(out,"\t addr=0x%"PRIx64"\tret=%"PRIu64" is done.\n",*addr,ret);
            qemu_plugin_outs(out->str);
#ifdef CONFIG_2nd_CCACHE
            if(second_ccache_flag!=TRACK){
                switch_mode(TRACK,false, 0);
            }
#endif
        }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    tb_ip *tbIp;
    ALLOC_SET0(tbIp,tb_ip);

    size_t i;
    tb_num++;
    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
#ifdef CONFIG_2nd_CCACHE
        if (i==0){
            tbIp->ip=qemu_plugin_insn_vaddr(insn);
        }
#endif
        mem_callback_argument *mem_cb_arg = NULL;
        void *usr_data=NULL;
        CB_TYPE cbType=AFTER;
        inst_callback_argument *cb_args=NULL;
        cs_insn *cs_ptr = (cs_insn*)cap_plugin_insn_disas(insn);
        cs_x86 *inst_det = &cs_ptr->detail->x86;

        qemu_plugin_vcpu_udata_cb_t cb=NULL;

        cb_args = analyze_Operands(inst_det->operands,inst_det->op_count);

        switch(cs_ptr->id){
            case X86_INS_CMOVA:
            case X86_INS_CMOVAE:
            case X86_INS_CMOVB:
            case X86_INS_CMOVBE:
            case X86_INS_CMOVE:
            case X86_INS_CMOVG:
            case X86_INS_CMOVGE:
            case X86_INS_CMOVL:
            case X86_INS_CMOVLE:
            case X86_INS_CMOVNE:
            case X86_INS_CMOVNO:
            case X86_INS_CMOVNP:
            case X86_INS_CMOVNS:
            case X86_INS_CMOVO:
            case X86_INS_CMOVP:
            case X86_INS_CMOVS:
            /* the above should propagate conditionally but we approximate here by always propagating. The src is never imm for them so the check below never applies */
//            case X86_INS_MOVD:
            /* MOVD can also be used for XMM but rn only r/m32, mm and reverse would work */
            case X86_INS_MOVABS:
            case X86_INS_MOVZX:
            case X86_INS_MOV:
                 //better to take this outside, and set it to NULL for otherwise case
                cb_args->src.type==IMMEDIATE?(cb = taint_cb_clear):(cb = taint_cb_mov);
                nice_print(cs_ptr);
                break;
            case X86_INS_BSF:
            case X86_INS_BSR:
                //similar to mov but also affects flags
                cb = taint_cb_movwf;
                nice_print(cs_ptr);
                break;
            case X86_INS_BT:
            case X86_INS_BTC:
            case X86_INS_BTR:
            case X86_INS_BTS:
                //only propagate conservatively to the flags
                cb = taint_cb_SETF;
                nice_print(cs_ptr);
                break;
            case X86_INS_PUSH:
                cb_args->dst.type = MEMORY;
                cb_args->dst.size = cb_args->src.size;
                cb_args->src.type==IMMEDIATE?(cb = taint_cb_clear):(cb = taint_cb_mov);
                nice_print(cs_ptr);
                break;
            case X86_INS_POP:
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.type = MEMORY;
                cb_args->src.addr.vaddr = 0;
                cb_args->src.type==IMMEDIATE?(cb = taint_cb_clear):(cb = taint_cb_mov);
                nice_print(cs_ptr);
                break;
              /*dst = LEFT(UNION(src1,SHIFT(src2,sh_val)))*/
            case X86_INS_LEA:
                nice_print(cs_ptr);
                cb = analyze_LEA_Addr(cb_args,&inst_det->operands[0].mem);
                break;
            case X86_INS_SUB:
            case X86_INS_ADD:
                if (cb_args->src.type==IMMEDIATE){
                    cb = taint_cb_EXTENDL; //we need a left extension like inc/dec but the instruction had two operands
                    copy_inq(cb_args->dst, cb_args->src); //copy dst to src
                }
                else{
                    copy_inq(cb_args->dst,cb_args->src2);
                    cb = taint_cb_ADD_SUB;
                }
                nice_print(cs_ptr);
                break;
            case X86_INS_ADC:
            case X86_INS_SBB:
                cb = taint_cb_ADC_SBB;
                nice_print(cs_ptr);
                break;
            case X86_INS_CMP:
                cb = taint_cb_CMP; //another version of Add/SUB without storing the shadow result
                nice_print(cs_ptr);
                break;
            case X86_INS_NEG:
            case X86_INS_INC:
            case X86_INS_DEC:
                copy_inq(cb_args->src,cb_args->dst); //has only one operand, only src is valid
                cb = taint_cb_EXTENDL;
                nice_print(cs_ptr);
                break;
            case X86_INS_CBW:
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.type = GLOBAL;
                cb_args->src.addr.id = R_AL;
                cb_args->src.size = SHD_SIZE_u8;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.addr.id = R_AH;
                cb_args->dst.size = SHD_SIZE_u8;
                cb = taint_cb_EXTENDL;
                nice_print(cs_ptr);
                break;
            case X86_INS_CWD:
            ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.type = GLOBAL;
                cb_args->src.addr.id = R_EAX;
                cb_args->src.size = SHD_SIZE_u16;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.addr.id = R_EDX;
                cb_args->dst.size = SHD_SIZE_u16;
                cb = taint_cb_EXTENDL;
                nice_print(cs_ptr);
                break;
            case X86_INS_CWDE:
            case X86_INS_CQO: //cqto
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.type = GLOBAL;
                cb_args->src.addr.id = R_EAX;
                cb_args->src.size = SHD_SIZE_u16;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.addr.id = R_EAX;
                cb_args->dst.size = SHD_SIZE_u32;
                cb = taint_cb_EXTENDL;
                nice_print(cs_ptr);
                break;
            case X86_INS_CDQ:
            case X86_INS_CDQE: //cltq
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.type = GLOBAL;
                cb_args->src.addr.id = R_EAX;
                cb_args->src.size = SHD_SIZE_u32;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.addr.id = R_EAX;
                cb_args->dst.size = SHD_SIZE_u64;
                cb = taint_cb_EXTENDL;
                nice_print(cs_ptr);
                break;
            case X86_INS_MOVSX:
            case X86_INS_MOVSXD:
                cb = taint_cb_EXTENDL;
                //print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                nice_print(cs_ptr);
                break;
            case X86_INS_XOR:
                if (cb_args->src.type==IMMEDIATE){
                    cb = taint_cb_mov;
                    copy_inq(cb_args->dst, cb_args->src);
                }
                else{
                    cb = taint_cb_XOR;
                }
                nice_print(cs_ptr);
                break;
            case X86_INS_SHR:
            case X86_INS_SAR:
            case X86_INS_SHL:
            case X86_INS_ROR:
            case X86_INS_ROL:
//          case X86_INS_SAL: //not included in memcheck shift rules
                set_opId(cs_ptr->id,cb_args->operation); //sets proper cb_args->operation enum value
                cb = taint_cb_SR;
                nice_print(cs_ptr);
                break;
            case X86_INS_AND:
            case X86_INS_OR:
                set_opId(cs_ptr->id,cb_args->operation);
                cb = taint_cb_AND_OR;
                ALLOC_SET0(cb_args->vals,inst_callback_values);
                qemu_plugin_register_vcpu_insn_exec_cb(
                        insn, op_record_values , QEMU_PLUGIN_CB_NO_REGS, (void *)cb_args);
//                cbType = BEFORE;
                nice_print(cs_ptr);
                break;
            case X86_INS_TEST:
                cb = taint_cb_TEST;
                nice_print(cs_ptr);
                break;
            case X86_INS_XCHG:
                cb = taint_cb_XCHG;
                nice_print(cs_ptr);
                break;
            case X86_INS_CMPXCHG:
                cb = taint_cb_CMPCHG;
                nice_print(cs_ptr);
                break;
            case X86_INS_IMUL:
            case X86_INS_IDIV:
                if (inst_det->op_count==2){
                    copy_inq(cb_args->dst, cb_args->src2);
                    cb = taint_cb_ADD_SUB;
                    nice_print(cs_ptr);
                    break;
                }
                else if (inst_det->op_count==3){
                    copy_inq(cb_args->src2, cb_args->src); //copy dst to src
                    cb = taint_cb_EXTENDL; //we need a left extension
//                    print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                    nice_print(cs_ptr);
                    break;
                }
            case X86_INS_MUL:
            case X86_INS_DIV:
                cb = taint_cb_MUL_DIV;
                nice_print(cs_ptr);
                break;
            case X86_INS_SYSCALL: //tainting input is handled in system call cb
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb = taint_cb_SYSCALL;
                nice_print(cs_ptr);
                break;
            case X86_INS_NOP:
            case X86_INS_NOT:
                free(cb_args);
                cb_args = NULL;
                nice_print(cs_ptr); //implemented but NOT wouldn't change the taint status
                break;
            case X86_INS_JAE:
            case X86_INS_JA:
            case X86_INS_JBE:
            case X86_INS_JB:
            case X86_INS_JCXZ:
            case X86_INS_JECXZ:
            case X86_INS_JE:
            case X86_INS_JGE:
            case X86_INS_JG:
            case X86_INS_JLE:
            case X86_INS_JL:
            case X86_INS_JNE:
            case X86_INS_JNO:
            case X86_INS_JNP:
            case X86_INS_JNS:
            case X86_INS_JO:
            case X86_INS_JP:
            case X86_INS_JS:
                cb_args->operation = COND_JMP;
//            case X86_INS_JRCXZ: special instruction, checks registers instead of flags
            case X86_INS_JMP:
                cb = taint_cb_JUMP;
                cbType = cb_args->src.type==MEMORY?INMEM:BEFORE;
                nice_print(cs_ptr);
                break;
            case X86_INS_CALL:
                cb_args->src2.addr.id = R_EIP;
                cb_args->src2.type = GLOBAL;
                cb_args->src2.size = SHD_SIZE_u64;
                cb_args->dst.addr.id = R_ESP;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.size = SHD_SIZE_u64;
                cbType = BEFORE;
                cb = taint_cb_CALL;
                nice_print(cs_ptr);
                break;
            case X86_INS_RET:
                cb_args = malloc(sizeof(inst_callback_argument));
                cb_args->src.addr.id = R_ESP;
                cb_args->src.type = GLOBAL;
                cb_args->src.size = SHD_SIZE_u64;
                cb_args->dst.addr.id = R_EIP;
                cb_args->dst.type = GLOBAL;
                cb_args->dst.size = SHD_SIZE_u64;
                cb = taint_cb_RET;
                cbType = BEFORE;
                nice_print(cs_ptr);
                break;
            case X86_INS_CPUID:
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb = taint_cb_CPUID;
                nice_print(cs_ptr);
                break;
            case X86_INS_RDTSC:
                //print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb = taint_cb_RDTSC;
                nice_print(cs_ptr);
                break;
            case X86_INS_LEAVE:
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.type = MEMORY;
                cb_args->src.size = SHD_SIZE_u64;
                cb = taint_cb_LEAVE;
                nice_print(cs_ptr);
                break;
            case X86_INS_SETAE:
            case X86_INS_SETA:
            case X86_INS_SETBE:
            case X86_INS_SETB:
            case X86_INS_SETE:
            case X86_INS_SETGE:
            case X86_INS_SETG:
            case X86_INS_SETLE:
            case X86_INS_SETL:
            case X86_INS_SETNE:
            case X86_INS_SETNO:
            case X86_INS_SETNP:
            case X86_INS_SETNS:
            case X86_INS_SETO:
            case X86_INS_SETP:
            case X86_INS_SETS:
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.addr.id = 0;
                cb_args->src.type = FLAG;
                cb_args->src.size = SHD_SIZE_u8;
                cb = taint_cb_mov;
                nice_print(cs_ptr);
                break;
            case X86_INS_STOSB:
            case X86_INS_STOSW:
            case X86_INS_STOSD:
            case X86_INS_STOSQ:
                //the problem is that inserting the cb after the instruction is too late (never hit), and before is too soon; we don't have the address.
                //we should compute the effective address
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src.type=GLOBAL;
//                cb_args->src.size=cb_args->dst.size; already set to that
                cb = taint_cb_mov;
//                cb = taint_cb_STOS;
                cbType = INMEM;
//                print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                nice_print(cs_ptr);
                break;
            default:
                if(inst_det->op_count==2){ // a majority of SSE instructions are handled here
                    cb = cb_args->src.type==IMMEDIATE? taint_cb_clear : taint_cb_conservative;
                    nice_print(cs_ptr);
                }
                else if(inst_det->op_count==3){
                    if (cb_args->src.type==IMMEDIATE){
                        copy_inq(cb_args->src2,cb_args->src);
                        cb = taint_cb_conservative;
                        nice_print(cs_ptr);
                    }
                    else if(cb_args->src2.type==IMMEDIATE){
                        cb = taint_cb_conservative;
                        nice_print(cs_ptr);
                    }
                }
                else{
                    free(cb_args);
                    cb_args = NULL;
                    handle_unsopported_ins(cs_ptr, unsupported_ins_log);
                }
                break;
        }
        //register memory callback to get the vaddr if one of the operands is mem
        if (cb_args!=NULL){
            //usr_data should be allocated
            usr_data = (void*)cb_args;
            if (cb_args->src.type == MEMORY){
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->src.addr.vaddr);
                mem_cb_arg->ip = qemu_plugin_insn_vaddr(insn);
            }
            else if (cb_args->dst.type == MEMORY){
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->dst.addr.vaddr);
                mem_cb_arg->ip = qemu_plugin_insn_vaddr(insn);
            }

        }
        if (mem_cb_arg!=NULL){
            qemu_plugin_register_vcpu_mem_cb(insn, op_mem,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             QEMU_PLUGIN_MEM_RW, (void *)mem_cb_arg);
        }
        //register the selected callback
        if(cb!=NULL && usr_data!=NULL
#ifdef CONFIG_2nd_CCACHE
                                    && second_ccache_flag
#endif
                                    ){
            switch(cbType){
                case AFTER:
                    qemu_plugin_register_vcpu_after_insn_exec_cb(
                            insn, cb , QEMU_PLUGIN_CB_NO_REGS, usr_data);
                    break;
                case BEFORE:
                    qemu_plugin_register_vcpu_insn_exec_cb(
                            insn, cb , QEMU_PLUGIN_CB_NO_REGS, usr_data);
                    break;
                case INMEM:
                    mem_cb_arg->args = cb_args;
                    mem_cb_arg->callback = cb;
                    break;
                default:
                    printf("this callback type is not supported!\n");
                    assert(0);
            }
        }
//        if (i==n-1){
//            tb_ip *tbIp;
//            ALLOC_SET0(tbIp,tb_ip);
//            tbIp->ip=qemu_plugin_insn_vaddr(insn);
//            tbIp->tb = tb_num;
//            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_tb_exec,
//                                                         QEMU_PLUGIN_CB_NO_REGS,
//                                                         (void *)tbIp);
//        }
    }
#ifdef CONFIG_2nd_CCACHE
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, (void *)tbIp);
#endif

}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    for (i = 0; i < argc; i++) {
        char *p = argv[i];
        if (strcmp(p, "inline") == 0) {
            do_inline = true;
        } else if (strcmp(p, "verbose") == 0) {
            verbose = true;
        }
    }

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_syscall_cb(id, syscall_callback);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_ret_callback);
    return 0;
}
