//
// Created by sina on 4/28/20.
//

#include <stdlib.h>
#include <qemu-plugin.h>
#include "lib/tainting.h"
#include "lib/taint_propagation.c"
#include "lib/shadow_memory.c"
//#define DEBUG_MEMCB
//#define LOG_INS
//#define DEBUG_CB
#define DEBUG_SYSCALL 0

typedef struct{
    uint64_t ip;
    int tb;
} tb_ip;
int tb_num=0;
int tb_switched = -1;
#define READ_VALUE(inq,buf) switch(inq.type){ \
                                case GLOBAL:\
                                    plugin_reg_read(inq.addr.id,inq.size,buf);\
                                    break;\
                                case MEMORY:\
                                    plugin_mem_read(inq.addr.vaddr,inq.size,buf);\
                                    break;\
                                case IMMEDIATE:\
                                    *(uint64_t *)buf = inq.addr.vaddr; \
                                    break;\
                                default:\
                                    break;\
                            }


#ifdef DEBUG_CB
#define DEBUG_OUTPUT(arg, inst_s) g_autofree gchar *o1=g_strdup_printf("%s: src=0x%lx, size=%d, type=%d\t src2=0x%lx, size=%d, type=%d\t dst=0x%lx, size=%d, type=%d\n",inst_s,\
                                  arg->src.addr.vaddr, arg->src.size, arg->src.type,arg->src2.addr.vaddr, arg->src2.size, arg->src2.type,arg->dst.addr.vaddr, arg->dst.size, arg->dst.type);\
                                  qemu_plugin_outs(o1);
#else
#define DEBUG_OUTPUT(arg, inst_s)
#endif

#define INIT_ARG(arg,udata)  inst_callback_argument *arg;\
                             if (udata!=NULL){\
                                arg = (inst_callback_argument *)udata;\
                             } else{assert(0);}\

#define OUTPUT_ERROR(err, arg, inst_s)  if (err){\
                                    g_autofree gchar *o2 = g_strdup_printf("SHADOW error in %s inst callback#\toperands: src=%lx, dst=%lx\n",inst_s, arg->src.addr.vaddr, arg->dst.addr.vaddr);\
                                    qemu_plugin_outs(o2);}

#ifdef DEBUG_MEMCB
#define DEBUG_MEMCB_OUTPUT(vaddr)  {\
                                    g_autofree gchar *o2 = g_strdup_printf("#op_mem callback#\tvaddr=%lx\n",*(uint64_t *)(vaddr));\
                                    qemu_plugin_outs(o2);}
#else
#define DEBUG_MEMCB_OUTPUT(vaddr)
#endif

#ifdef LOG_INS

#define nice_print(insn) print_id_groups(insn)

#else


static inline void nice_print(cs_insn *insn)
{
//    gchar *out;
//    GString *report;
    switch(insn->id) {
//        case X86_INS_CMP:
//        case X86_INS_CMPXCHG:
//            out = g_strdup_printf("num_operands: %d, op1=%" PRIu32 ", op2=%" PRIu32 "\n", insn->detail->x86.op_count, insn->detail->x86.operands[0].reg, insn->detail->x86.operands[1].reg);
//            qemu_plugin_outs(out);
//            break;
//        case X86_INS_LEA:
//            report = g_string_new("*X86_INS_LEA*\t");
//            print_mem_op(&insn->detail->x86.operands[0].mem, report);
//            qemu_plugin_outs(report->str);
//            break;
//        case X86_INS_CQO: //cqto
//        case X86_INS_CLTS:
//        case X86_INS_CWD:
//        case X86_INS_CWDE:
//        case X86_INS_CDQ:
//        case X86_INS_CDQE: //cltq
//        case X86_INS_STOSB:
//        case X86_INS_STOSW:
//        case X86_INS_STOSD:
//        case X86_INS_STOSQ:
//            print_id_groups(insn);
//            break;
        default:
            break;
    }

}



#endif

static inline void handle_unsopported_ins(cs_insn *cs_i, GHashTable *log){
    char *inst = NULL;

    char *instance = (char *)g_hash_table_lookup(log, GUINT_TO_POINTER(cs_i->id));
    if (!instance) {
        inst = strdup(cs_i->mnemonic);
        g_hash_table_insert(log, GUINT_TO_POINTER(cs_i->id),(gpointer)inst);
#ifdef LOG_INS
        print_ops(cs_i->mnemonic, cs_i->op_str);
        print_id_groups(cs_i);
#endif
    }
    //log(report,"0x%lx -> 0x%lx!\n",id,shadow);
}

static inline void print_unsupported_ins(GString *report_str,GHashTable *log){
    GList *ins = g_hash_table_get_values(log);
    if (ins && g_list_next(ins)) {
        while (g_list_next(ins)) {
            ins = g_list_next(ins);
            char *rec = (char *) ins->data;
            g_string_append_printf(report_str,
                                   "Unsupported Instr: %s\n",rec);
        }
        g_list_free(ins);
    }
}

#define set_opId(id,op) switch(id){\
                        case X86_INS_SHR:\
                            op = Shr;\
                            break;\
                        case X86_INS_SAR:\
                            op = Sar;\
                            break;\
                        case X86_INS_SHL:\
                            op = Shl;\
                            break;\
                        case X86_INS_SAL:\
                            op = Sal;\
                            break;\
                        case X86_INS_ROL:\
                            op = Rol;\
                            break;\
                        case X86_INS_ROR:\
                            op = Ror;\
                            break;\
                        case X86_INS_AND:\
                            op = OP_AND;\
                            break;\
                        case X86_INS_OR:\
                            op = OP_OR;\
                            break;\
                        default:\
                            assert(0);\
                        }


static void taint_cb_mov(unsigned int cpu_index, void *udata){ //use taint_cb prefix instead of SHD
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_mov");
//    uint8_t buf_dst_val[SHD_SIZE_MAX]={0};
//    READ_VALUE(arg->dst,buf_dst_val);
    err = SHD_copy(arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"MOV");
//    free(udata); //no need to free right away, a cb for an instance of an instruction might be called several times!
}

//static void taint_cb_STOS(unsigned int cpu_index, void *udata){ //would have been usefull if the CB after STOS would be hit which is not the case
//    shadow_err err = 0;
//    INIT_ARG(arg,udata);
//    DEBUG_OUTPUT(arg,"taint_cb_STOS");
//    uint8_t value=0;
//    uint8_t buf_dst_val[SHD_SIZE_MAX]={0};
//    read repetition size from the guest, the callback would be called ecx times so no need to
//    shad_inq regECX = {.addr.id=MAP_X86_REGISTER(X86_REG_RCX),.type=GLOBAL, .size=SHD_SIZE_u32};
//    READ_VALUE(regECX,buf_dst_val);
//    uint32_t count = *(uint32_t *)(buf_dst_val);
//    shad_inq regEAX = {.addr.id=MAP_X86_REGISTER(X86_REG_RAX),.type=GLOBAL, .size=SHD_SIZE_u32};
//    g_autofree gchar *report = g_strdup_printf("\nin taint_cb_STOS, type=%d addr_src=0x%lx dst_type=%d, addr_dst=%d\n",arg->src.type,arg->src.addr.vaddr,arg->dst.type, arg->dst.addr.id);
//    qemu_plugin_outs(report);
//
////    read EAX shadow and pessimistically convert it to one byte

//    SHD_value eax_shadow = SHD_get_shadow(regEAX);
//    err = SHD_cast(&eax_shadow,sizeof(SHD_value),&value,sizeof(uint8_t));
//    OUTPUT_ERROR(err,arg,"STOS error casting EAX taint");
////    finally copy
//    err = SHD_write_contiguous(arg->src.addr.vaddr, count, value);
//    OUTPUT_ERROR(err,arg,"STOS error copy");
//}


static void taint_cb_movwf(unsigned int cpu_index, void *udata){ //use taint_cb prefix instead of SHD
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_movwf");

    err = SHD_copy(arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"MOV");

    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    err = SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"MOV flags propagation");
}

static void taint_cb_SETF(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_SETF");

    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    err = SHD_copy_conservative(arg->src,&flags);
    OUTPUT_ERROR(err,arg,"FLAG propagation");
}

static void taint_cb_clear(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_clear");
    err = SHD_clear(&arg->dst);
    OUTPUT_ERROR(err,arg,"CLEAR");
}

static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_ADD_SUB");
    err = SHD_add_sub(arg->src,arg->src2,&arg->dst);
    //handle eflags
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"ADD/SUB");
}


static void taint_cb_ADC_SBB(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_ADDC_SBB");
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    err = SHD_CAddSub(arg->src,arg->dst,flags,&arg->dst);
    //handle eflags
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"ADC/SBB");
}

static void taint_cb_LEA(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    int shift_val = 0;
    DEBUG_OUTPUT(arg,"taint_cb_LEA\t*HERE*");

    if(arg->src3.type == IMMEDIATE && arg->src3.addr.vaddr!=0){ //shift index at src
        shift_val = arg->src3.addr.vaddr;
    }
    SHD_LEA(arg->src,arg->src2,shift_val,&arg->dst);
    OUTPUT_ERROR(err,arg,"LEA");
}

static void taint_cb_EXTENDL(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_EXTENDL");
    err = SHD_extensionL(arg->src,&arg->dst);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"INC/DEC");
}

static void taint_cb_CMP(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CMP");
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    err = SHD_CMP(arg->src,arg->dst,flags);
    OUTPUT_ERROR(err,arg,"CMP");
}

static void taint_cb_XOR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_XOR");
    err = SHD_union(arg->src,&arg->dst);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"XOR");
}

/* A precise rule would need reading RAX and destination value before this instruction.
 * Here, we approximate by propagating based on either results of the instruction execution. */
static void taint_cb_CMPCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CMPCHG");
    shad_inq regEAX = {.addr.id=MAP_X86_REGISTER(X86_REG_RAX),.type=GLOBAL, .size=arg->dst.size};
    err = SHD_union(arg->dst,&regEAX); //if eax=dst part that we conservatively propagate
    OUTPUT_ERROR(err,arg,"CMPCHG propagate from dst to EAX");
    err = SHD_union(arg->src,&arg->dst); //else EAX=dst that again we conservatively propagate
    OUTPUT_ERROR(err,arg,"CMPCHG propagate from src to dst");
}

static void taint_cb_SR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_SR");
    err = SHD_Shift_Rotation(arg->src,&arg->dst,arg->operation);
    OUTPUT_ERROR(err,arg,"SHIFT/ROTATION");
}

static void taint_cb_XCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_XCHG");
    err = SHD_exchange(&arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"XCHG");
}

static void taint_cb_AND_OR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_AND_OR");
//    g_autofree gchar *report = g_strdup_printf("\nin taint_cb_AND_OR, read values src_val=%lx, dst_val=%lx\n",arg->vals->src_val,arg->vals->dst_val);
//    qemu_plugin_outs(report);

    err = SHD_and_or(arg->src,&arg->dst,(void *)&arg->vals->src_val,(void *)&arg->vals->dst_val,arg->operation);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"XCHG");
}

static void taint_cb_TEST(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_TEST");
    uint8_t buf_src_val[SHD_SIZE_MAX]={0};
    uint8_t buf_dst_val[SHD_SIZE_MAX]={0};
    READ_VALUE(arg->src,buf_src_val);
    READ_VALUE(arg->dst,buf_dst_val);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    err = SHD_test(arg->src,arg->dst,flags,buf_src_val,buf_dst_val);
    OUTPUT_ERROR(err,arg,"TEST");
}

static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    arg->dst.type = GLOBAL;
    switch(arg->src.size){
        case SHD_SIZE_u8:
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_AX);
            arg->dst.size = SHD_SIZE_u16;
            break;
        case SHD_SIZE_u16:
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_AX);
            arg->dst.size = SHD_SIZE_u16;
            err = SHD_add_sub(arg->src,arg->dst,&arg->dst);
            OUTPUT_ERROR(err,arg,"Mul");
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_DX);
            break;
        case SHD_SIZE_u32:
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_EAX);
            arg->dst.size = SHD_SIZE_u32;
            err = SHD_add_sub(arg->src,arg->dst,&arg->dst);
            OUTPUT_ERROR(err,arg,"Mul");
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_EDX);
            break;
        case SHD_SIZE_u64:
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_RAX);
            arg->dst.size = SHD_SIZE_u64;
            err = SHD_add_sub(arg->src,arg->dst,&arg->dst);
            OUTPUT_ERROR(err,arg,"Mul");
            arg->dst.addr.id = MAP_X86_REGISTER(X86_REG_RDX);
            break;
        default:
            assert(0);
    }
    DEBUG_OUTPUT(arg,"taint_cb_MUL_DIV");
    err = SHD_add_sub(arg->src,arg->dst,&arg->dst);//the first propagation for 1 byte case, and the 2nd otherwise.

    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);

    OUTPUT_ERROR(err,arg,"Mul");
}

static void taint_cb_JUMP(unsigned int cpu_index, void *udata) {
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_JUMP");
    arg->src.type = MEMORY;
    SHD_value jmp_addr = SHD_get_shadow(arg->src);
    jmp_addr!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"JUMP *** address 0x%lx is tainted ***");
    if(arg->operation==COND_JMP){
        shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
        SHD_value flags_shadow = SHD_get_shadow(flags);
        OUTPUT_ERROR(flags_shadow!=0,arg,"JUMP *** flags are tainted ***");
    }
}
static void taint_cb_CALL(unsigned int cpu_index, void *udata) {
    shadow_err err = 0;
    INIT_ARG(arg,udata);
//    printf("taint_cb_CALL\n");
    DEBUG_OUTPUT(arg,"taint_cb_CALL");
    READ_VALUE(arg->dst, &arg->dst.addr.vaddr); //we need the value of stack register, we use the value as a memory address to store the eip taint
    arg->dst.type = MEMORY;
    err = SHD_copy(arg->src2,&arg->dst);

    OUTPUT_ERROR(err,arg,"CALL error storing the eip taint");
    //check the destination address
    arg->src.type = MEMORY;
    SHD_value jmp_addr = SHD_get_shadow(arg->src);
    jmp_addr!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"CALL *** destination function address is tainted ***");
//    printf("leaving taint_cb_CALL\n");
}

static void taint_cb_RET(unsigned int cpu_index, void *udata) { //reverse of CALL, RET target is one put in the dst read from stack
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_RET");

    READ_VALUE(arg->src, &arg->src.addr.vaddr);
    arg->src.type = MEMORY;
    err = SHD_copy(arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"RET error storing the stack taint");
    //check the destination address
    SHD_value jmp_addr = SHD_get_shadow(arg->dst);
    jmp_addr!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"RET *** destination function address is tainted ***");
}

static void taint_cb_CPUID(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CPUID");
    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
    arg->src.type=GLOBAL;
    arg->src.size=SHD_SIZE_u64;
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"CPUID error clearing RAX");

    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RBX);
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"CPUID error clearing RBX");

    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RCX);
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"CPUID error clearing RCX");

    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"CPUID error clearing RDX");
}

static void taint_cb_RDTSC(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_RDTSC");
    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
    arg->src.type=GLOBAL;
    arg->src.size=SHD_SIZE_u64;
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"RDTSC error clearing RAX");

    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
    err = SHD_clear(&arg->src);
    OUTPUT_ERROR(err,arg,"RDTSC error clearing RDX");
}

static void taint_cb_LEAVE(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);

    arg->src2.addr.id=MAP_X86_REGISTER(X86_REG_RBP);
    arg->src2.type=GLOBAL;
    arg->src2.size=SHD_SIZE_u64;

    arg->dst.addr.id=MAP_X86_REGISTER(X86_REG_RSP);
    arg->dst.type=GLOBAL;
    arg->dst.size=SHD_SIZE_u64;

    DEBUG_OUTPUT(arg,"taint_cb_LEAVE");
//    g_autofree gchar *report = g_strdup_printf("\nin taint_cb_LEAVE, mem_addr=0x%lx\n",arg->src.addr.vaddr);
//    qemu_plugin_outs(report);
    err = SHD_copy(arg->src2,&arg->dst);
    OUTPUT_ERROR(err,arg,"LEAVE error copying RBP shadow to RSP");
    err = SHD_copy(arg->src,&arg->src2);
    OUTPUT_ERROR(err,arg,"LEAVE error copying MEM shadow to RBP");
}
static void taint_cb_SYSCALL(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RCX);
    arg->src.type=GLOBAL;
    arg->src.size=SHD_SIZE_u64;
    arg->dst.addr.id=MAP_X86_REGISTER(X86_REG_RSP);
    arg->dst.type=GLOBAL;
    arg->dst.size=SHD_SIZE_u64;
    DEBUG_OUTPUT(arg,"taint_cb_SYSCALL");
    err = SHD_copy(arg->src,&arg->dst);

    arg->src.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
    arg->dst.addr.id=MAP_X86_REGISTER(X86_REG_RIP);
    err = SHD_copy(arg->src,&arg->dst);

    OUTPUT_ERROR(err,arg,"SYSCALL");
}

static void taint_cb_conservative(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_conservative");

    err = SHD_copy_conservative(arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"Conservative copy");
}

static void print_shadow(gpointer key, gpointer value){
    SHD_value shadow = *(SHD_value *)value;
    uint64_t id = *(uint64_t *)key;
    g_string_append_printf(report,"0x%lx -> 0x%lx!\n",id,shadow);
}

static void taint_list_all(void){
    report = g_string_new("------Listing register shadows------\n");
    SHD_list_global(print_shadow);
    g_string_append_printf(report,"----------------------------------\n");

    g_string_append_printf(report,"------Listing memory shadows------\n");
    SHD_list_mem(print_shadow);
    g_string_append_printf(report,"----------------------------------\n");

    g_string_append_printf(report,"-------Listing temp shadows-------\n");
    SHD_list_temp(print_shadow);
    g_string_append_printf(report,"----------------------------------\n");

    qemu_plugin_outs(report->str);
}
#ifdef CONFIG_2nd_CCACHE
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    tb_ip *tbIp = (tb_ip *)udata;
    shadow_err err;
    if(second_ccache_flag==TRACK){
        err = check_registers(R_EAX,R_EIP);
        if (err==0){
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
            printf("registers clean for tb=%d, ip=%lx\n",tbIp->tb,tbIp->ip);
#endif
            switch_mode(CHECK,true,tbIp->ip);
        }
    }
}
#endif