//
// Created by sina on 4/29/20.
//
#include <capstone.h>
#include "utility.h"
#define INVALID_REGISTER X86_REG_ENDING+1
#define MAP_X86_REGISTER(CAP_ID) x86_regs_mapping[CAP_ID]

static uint32_t x86_regs_mapping[X86_REG_ENDING] = {INVALID_REGISTER};
void init_register_mapping(void);

#define NUM_MAPPED_REGISTERS 92
const uint32_t caps_x86_regs[NUM_MAPPED_REGISTERS] = {
        X86_REG_AH, // R_AH
        X86_REG_AL, //R_AL
        X86_REG_AX, //R_EAX
        X86_REG_BH, //R_BH
        X86_REG_BL, //R_BL
        X86_REG_BP, //R_EBP
        X86_REG_BPL, //R_EBP
        X86_REG_BX, //R_EBX
        X86_REG_CH, //R_CH
        X86_REG_CL, //R_CL
        X86_REG_CX, //R_ECX
        X86_REG_DH, //R_DH
        X86_REG_DI, //R_EDI
        X86_REG_DIL, //R_EDI
        X86_REG_DL, //R_DL
        X86_REG_DX, //R_EDX
        X86_REG_EAX, //R_EAX
        X86_REG_EBP, //R_EBP
        X86_REG_EBX, //R_EBX
        X86_REG_ECX, //R_ECX
        X86_REG_EDI, //R_EDI
        X86_REG_EDX, //R_EDX
        X86_REG_ES, //R_ESI
        X86_REG_ESI, //R_ESI
        X86_REG_ESP, //R_ESP
        X86_REG_RAX, //R_EAX
        X86_REG_RBP, //R_EBP
        X86_REG_RBX, //R_EBX
        X86_REG_RCX, //R_ECX
        X86_REG_RDI, //R_EDI
        X86_REG_RDX, //R_EDX
        X86_REG_RSI, //R_ESI
        X86_REG_RSP, //R_ESP
        X86_REG_SI, //R_ESI
        X86_REG_SIL, //R_ESI
        X86_REG_SP, //R_ESP
        X86_REG_SPL, //R_ESP
        X86_REG_R8, //R_R8
        X86_REG_R9, //R_R9
        X86_REG_R10, //R_R10
        X86_REG_R11, //R_R11
        X86_REG_R12, //R_R12
        X86_REG_R13, //R_R13
        X86_REG_R14, //R_R14
        X86_REG_R15, //R_R15
        X86_REG_RIP,
        X86_REG_ES, //R_ES
        X86_REG_CS, //R_CS
        X86_REG_SS, //R_SS
        X86_REG_DS, //R_DS
        X86_REG_FS, //R_FS
        X86_REG_GS, //R_GS
        X86_REG_MM0,
        X86_REG_MM1,
        X86_REG_MM2,
        X86_REG_MM3,
        X86_REG_MM4,
        X86_REG_MM5,
        X86_REG_MM6,
        X86_REG_MM7,
        X86_REG_XMM0,
        X86_REG_XMM1,
        X86_REG_XMM2,
        X86_REG_XMM3,
        X86_REG_XMM4,
        X86_REG_XMM5,
        X86_REG_XMM6,
        X86_REG_XMM7,
        X86_REG_XMM8,
        X86_REG_XMM9,
        X86_REG_XMM10,
        X86_REG_XMM11,
        X86_REG_XMM12,
        X86_REG_XMM13,
        X86_REG_XMM14,
        X86_REG_XMM15,
        X86_REG_XMM16,
        X86_REG_XMM17,
        X86_REG_XMM18,
        X86_REG_XMM19,
        X86_REG_XMM20,
        X86_REG_XMM21,
        X86_REG_XMM22,
        X86_REG_XMM23,
        X86_REG_XMM24,
        X86_REG_XMM25,
        X86_REG_XMM26,
        X86_REG_XMM27,
        X86_REG_XMM28,
        X86_REG_XMM29,
        X86_REG_XMM30,
        X86_REG_XMM31,

};

const uint32_t qemu_x86_regs[NUM_MAPPED_REGISTERS] = {
        R_AH,
        R_AL,
        R_EAX,
        R_BH,
        R_BL,
        R_EBP,
        R_EBP,
        R_EBX,
        R_CH,
        R_CL,
        R_ECX,
        R_DH,
        R_EDI,
        R_EDI,
        R_DL,
        R_EDX,
        R_EAX,
        R_EBP,
        R_EBX,
        R_ECX,
        R_EDI,
        R_EDX,
        R_ESI,
        R_ESI,
        R_ESP,
        R_EAX,
        R_EBP,
        R_EBX,
        R_ECX,
        R_EDI,
        R_EDX,
        R_ESI,
        R_ESP,
        R_ESI,
        R_ESI,
        R_ESP,
        R_ESP,
        R_R8,
        R_R9,
        R_R10,
        R_R11,
        R_R12,
        R_R13,
        R_R14,
        R_R15,
        R_EIP,
        R_ES,
        R_CS,
        R_SS,
        R_DS,
        R_FS,
        R_GS,
        X86_REG_MM0,
        X86_REG_MM1,
        X86_REG_MM2,
        X86_REG_MM3,
        X86_REG_MM4,
        X86_REG_MM5,
        X86_REG_MM6,
        X86_REG_MM7,
        X86_REG_XMM0,
        X86_REG_XMM1,
        X86_REG_XMM2,
        X86_REG_XMM3,
        X86_REG_XMM4,
        X86_REG_XMM5,
        X86_REG_XMM6,
        X86_REG_XMM7,
        X86_REG_XMM8,
        X86_REG_XMM9,
        X86_REG_XMM10,
        X86_REG_XMM11,
        X86_REG_XMM12,
        X86_REG_XMM13,
        X86_REG_XMM14,
        X86_REG_XMM15,
        X86_REG_XMM16,
        X86_REG_XMM17,
        X86_REG_XMM18,
        X86_REG_XMM19,
        X86_REG_XMM20,
        X86_REG_XMM21,
        X86_REG_XMM22,
        X86_REG_XMM23,
        X86_REG_XMM24,
        X86_REG_XMM25,
        X86_REG_XMM26,
        X86_REG_XMM27,
        X86_REG_XMM28,
        X86_REG_XMM29,
        X86_REG_XMM30,
        X86_REG_XMM31,
};

void init_register_mapping(void){
    for (int i=0;i<NUM_MAPPED_REGISTERS;i++){
//        printf("cap reg=%d -> qemu reg=%d\n",caps_x86_regs[i],qemu_x86_regs[i]);
        x86_regs_mapping[caps_x86_regs[i]] = qemu_x86_regs[i];
    }
//    for (int i=0;i<X86_REG_ENDING;i++){
//        printf("i=%d -> reg=%d\n",i,x86_regs_mapping[i]);
//    }
}

static char *get_type(char* op){
    int i = 0;
    while (op[i++]==' ');
    char *operand = &op[i-1];
    switch(operand[0]){
        case '$':
            return strdup("imm");
        case '%':
            return strdup("reg");
        default:
            return strdup("mem");
    }
}

static inline void print_ops(char *opcode, char *i_dis){
    int i = 1;
    char *ops[4];
    ops[0] = opcode;
    char *ins_copy = strdup(i_dis);
    char* token = strtok(ins_copy, ",");

    // Keep separating tokens
    while (token != NULL && i<4) {
        ops[i++] = token;
        //printf("%s\n", token);
        token = strtok(NULL, ",");
    }
    //print somehow

    g_autofree gchar *d_str;
    switch(i){
        case 1:
            d_str = g_strdup_printf("UNSUPPORTED opcode: %s\n", ops[0]);
            break;
        case 2:
            d_str = g_strdup_printf("UNSUPPORTED opcode: %s, op1: %s \n", ops[0], get_type(ops[1]));
            break;
        case 3:
            d_str = g_strdup_printf("UNSUPPORTED opcode: %s, op1: %s (%s), op2: %s (%s)\n", ops[0], ops[1], get_type(ops[1]), ops[2], get_type(ops[2]));
            break;
        case 4:
            d_str = g_strdup_printf("UNSUPPORTED opcode: %s, op1: %s (%s), op2: %s (%s), op3: %s (%s)\n", ops[0], ops[1], get_type(ops[1]), ops[2], get_type(ops[2]), ops[3], get_type(ops[3]));
            break;
        default:
            g_assert_not_reached();
    }
    qemu_plugin_outs(d_str);
}

static inline void print_id_groups(cs_insn *cs_ptr){
    g_autoptr(GString) cs_str=g_string_new("cs_insn: ");
    g_string_append_printf(cs_str,"ptr=%p, id=%u, cmd=%s\t groups=%u, numops=%d", (void *)cs_ptr,cs_ptr->id,cs_ptr->mnemonic,cs_ptr->detail->groups_count,cs_ptr->detail->x86.op_count);
    if(cs_ptr->detail->groups_count>0){
        g_string_append_printf(cs_str,", groups[0]=%u\n",cs_ptr->detail->groups[0]);
    }
    else{
        g_string_append_printf(cs_str,"\n");
    }

    qemu_plugin_outs(cs_str->str);
}

static inline void print_reg_ids_test(GString *end_rep){
    g_string_append_printf(end_rep,"AX=0x%x, EAX=0x%x, RAX=0x%x\n",X86_REG_AX,X86_REG_EAX,X86_REG_RAX);
    g_string_append_printf(end_rep,"BX=0x%x, EBX=0x%x, RBX=0x%x\n",X86_REG_BX,X86_REG_EBX,X86_REG_RBX);
    g_string_append_printf(end_rep,"DX=0x%x, EDX=0x%x, RDX=0x%x\n",X86_REG_DX,X86_REG_EDX,X86_REG_RDX);
    g_string_append_printf(end_rep,"CX=0x%x, ECX=0x%x, RCX=0x%x\n",X86_REG_CX,X86_REG_ECX,X86_REG_RCX);

    g_string_append_printf(end_rep,"ID=> AX=0x%x, EAX=0x%x, RAX=0x%x\n",MAP_X86_REGISTER(X86_REG_AX),MAP_X86_REGISTER(X86_REG_EAX),MAP_X86_REGISTER(X86_REG_RAX));
    g_string_append_printf(end_rep,"ID=> BX=0x%x, EBX=0x%x, RBX=0x%x\n",MAP_X86_REGISTER(X86_REG_BX),MAP_X86_REGISTER(X86_REG_EBX),MAP_X86_REGISTER(X86_REG_RBX));
    g_string_append_printf(end_rep,"ID=> DX=0x%x, EDX=0x%x, RDX=0x%x\n",MAP_X86_REGISTER(X86_REG_DX),MAP_X86_REGISTER(X86_REG_EDX),MAP_X86_REGISTER(X86_REG_RDX));
    g_string_append_printf(end_rep,"ID=> CX=0x%x, ECX=0x%x, RCX=0x%x\n",MAP_X86_REGISTER(X86_REG_CX),MAP_X86_REGISTER(X86_REG_ECX),MAP_X86_REGISTER(X86_REG_RCX));
    g_string_append_printf(end_rep,"Done!\n");

}

typedef struct name_map {
    unsigned int id;
    const char *name;
} name_map;

static const name_map reg_name_maps[] = {
        { X86_REG_INVALID, NULL },

        { X86_REG_AH, "ah" },
        { X86_REG_AL, "al" },
        { X86_REG_AX, "ax" },
        { X86_REG_BH, "bh" },
        { X86_REG_BL, "bl" },
        { X86_REG_BP, "bp" },
        { X86_REG_BPL, "bpl" },
        { X86_REG_BX, "bx" },
        { X86_REG_CH, "ch" },
        { X86_REG_CL, "cl" },
        { X86_REG_CS, "cs" },
        { X86_REG_CX, "cx" },
        { X86_REG_DH, "dh" },
        { X86_REG_DI, "di" },
        { X86_REG_DIL, "dil" },
        { X86_REG_DL, "dl" },
        { X86_REG_DS, "ds" },
        { X86_REG_DX, "dx" },
        { X86_REG_EAX, "eax" },
        { X86_REG_EBP, "ebp" },
        { X86_REG_EBX, "ebx" },
        { X86_REG_ECX, "ecx" },
        { X86_REG_EDI, "edi" },
        { X86_REG_EDX, "edx" },
        { X86_REG_EFLAGS, "flags" },
        { X86_REG_EIP, "eip" },
        { X86_REG_EIZ, "eiz" },
        { X86_REG_ES, "es" },
        { X86_REG_ESI, "esi" },
        { X86_REG_ESP, "esp" },
        { X86_REG_FPSW, "fpsw" },
        { X86_REG_FS, "fs" },
        { X86_REG_GS, "gs" },
        { X86_REG_IP, "ip" },
        { X86_REG_RAX, "rax" },
        { X86_REG_RBP, "rbp" },
        { X86_REG_RBX, "rbx" },
        { X86_REG_RCX, "rcx" },
        { X86_REG_RDI, "rdi" },
        { X86_REG_RDX, "rdx" },
        { X86_REG_RIP, "rip" },
        { X86_REG_RIZ, "riz" },
        { X86_REG_RSI, "rsi" },
        { X86_REG_RSP, "rsp" },
        { X86_REG_SI, "si" },
        { X86_REG_SIL, "sil" },
        { X86_REG_SP, "sp" },
        { X86_REG_SPL, "spl" },
        { X86_REG_SS, "ss" },
        { X86_REG_CR0, "cr0" },
        { X86_REG_CR1, "cr1" },
        { X86_REG_CR2, "cr2" },
        { X86_REG_CR3, "cr3" },
        { X86_REG_CR4, "cr4" },
        { X86_REG_CR5, "cr5" },
        { X86_REG_CR6, "cr6" },
        { X86_REG_CR7, "cr7" },
        { X86_REG_CR8, "cr8" },
        { X86_REG_CR9, "cr9" },
        { X86_REG_CR10, "cr10" },
        { X86_REG_CR11, "cr11" },
        { X86_REG_CR12, "cr12" },
        { X86_REG_CR13, "cr13" },
        { X86_REG_CR14, "cr14" },
        { X86_REG_CR15, "cr15" },
        { X86_REG_DR0, "dr0" },
        { X86_REG_DR1, "dr1" },
        { X86_REG_DR2, "dr2" },
        { X86_REG_DR3, "dr3" },
        { X86_REG_DR4, "dr4" },
        { X86_REG_DR5, "dr5" },
        { X86_REG_DR6, "dr6" },
        { X86_REG_DR7, "dr7" },
        { X86_REG_FP0, "fp0" },
        { X86_REG_FP1, "fp1" },
        { X86_REG_FP2, "fp2" },
        { X86_REG_FP3, "fp3" },
        { X86_REG_FP4, "fp4" },
        { X86_REG_FP5, "fp5" },
        { X86_REG_FP6, "fp6" },
        { X86_REG_FP7, "fp7" },
        { X86_REG_K0, "k0" },
        { X86_REG_K1, "k1" },
        { X86_REG_K2, "k2" },
        { X86_REG_K3, "k3" },
        { X86_REG_K4, "k4" },
        { X86_REG_K5, "k5" },
        { X86_REG_K6, "k6" },
        { X86_REG_K7, "k7" },
        { X86_REG_MM0, "mm0" },
        { X86_REG_MM1, "mm1" },
        { X86_REG_MM2, "mm2" },
        { X86_REG_MM3, "mm3" },
        { X86_REG_MM4, "mm4" },
        { X86_REG_MM5, "mm5" },
        { X86_REG_MM6, "mm6" },
        { X86_REG_MM7, "mm7" },
        { X86_REG_R8, "r8" },
        { X86_REG_R9, "r9" },
        { X86_REG_R10, "r10" },
        { X86_REG_R11, "r11" },
        { X86_REG_R12, "r12" },
        { X86_REG_R13, "r13" },
        { X86_REG_R14, "r14" },
        { X86_REG_R15, "r15" },
        { X86_REG_ST0, "st(0" },
        { X86_REG_ST1, "st(1)" },
        { X86_REG_ST2, "st(2)" },
        { X86_REG_ST3, "st(3)" },
        { X86_REG_ST4, "st(4)" },
        { X86_REG_ST5, "st(5)" },
        { X86_REG_ST6, "st(6)" },
        { X86_REG_ST7, "st(7)" },
        { X86_REG_XMM0, "xmm0" },
        { X86_REG_XMM1, "xmm1" },
        { X86_REG_XMM2, "xmm2" },
        { X86_REG_XMM3, "xmm3" },
        { X86_REG_XMM4, "xmm4" },
        { X86_REG_XMM5, "xmm5" },
        { X86_REG_XMM6, "xmm6" },
        { X86_REG_XMM7, "xmm7" },
        { X86_REG_XMM8, "xmm8" },
        { X86_REG_XMM9, "xmm9" },
        { X86_REG_XMM10, "xmm10" },
        { X86_REG_XMM11, "xmm11" },
        { X86_REG_XMM12, "xmm12" },
        { X86_REG_XMM13, "xmm13" },
        { X86_REG_XMM14, "xmm14" },
        { X86_REG_XMM15, "xmm15" },
        { X86_REG_XMM16, "xmm16" },
        { X86_REG_XMM17, "xmm17" },
        { X86_REG_XMM18, "xmm18" },
        { X86_REG_XMM19, "xmm19" },
        { X86_REG_XMM20, "xmm20" },
        { X86_REG_XMM21, "xmm21" },
        { X86_REG_XMM22, "xmm22" },
        { X86_REG_XMM23, "xmm23" },
        { X86_REG_XMM24, "xmm24" },
        { X86_REG_XMM25, "xmm25" },
        { X86_REG_XMM26, "xmm26" },
        { X86_REG_XMM27, "xmm27" },
        { X86_REG_XMM28, "xmm28" },
        { X86_REG_XMM29, "xmm29" },
        { X86_REG_XMM30, "xmm30" },
        { X86_REG_XMM31, "xmm31" },
        { X86_REG_YMM0, "ymm0" },
        { X86_REG_YMM1, "ymm1" },
        { X86_REG_YMM2, "ymm2" },
        { X86_REG_YMM3, "ymm3" },
        { X86_REG_YMM4, "ymm4" },
        { X86_REG_YMM5, "ymm5" },
        { X86_REG_YMM6, "ymm6" },
        { X86_REG_YMM7, "ymm7" },
        { X86_REG_YMM8, "ymm8" },
        { X86_REG_YMM9, "ymm9" },
        { X86_REG_YMM10, "ymm10" },
        { X86_REG_YMM11, "ymm11" },
        { X86_REG_YMM12, "ymm12" },
        { X86_REG_YMM13, "ymm13" },
        { X86_REG_YMM14, "ymm14" },
        { X86_REG_YMM15, "ymm15" },
        { X86_REG_YMM16, "ymm16" },
        { X86_REG_YMM17, "ymm17" },
        { X86_REG_YMM18, "ymm18" },
        { X86_REG_YMM19, "ymm19" },
        { X86_REG_YMM20, "ymm20" },
        { X86_REG_YMM21, "ymm21" },
        { X86_REG_YMM22, "ymm22" },
        { X86_REG_YMM23, "ymm23" },
        { X86_REG_YMM24, "ymm24" },
        { X86_REG_YMM25, "ymm25" },
        { X86_REG_YMM26, "ymm26" },
        { X86_REG_YMM27, "ymm27" },
        { X86_REG_YMM28, "ymm28" },
        { X86_REG_YMM29, "ymm29" },
        { X86_REG_YMM30, "ymm30" },
        { X86_REG_YMM31, "ymm31" },
        { X86_REG_ZMM0, "zmm0" },
        { X86_REG_ZMM1, "zmm1" },
        { X86_REG_ZMM2, "zmm2" },
        { X86_REG_ZMM3, "zmm3" },
        { X86_REG_ZMM4, "zmm4" },
        { X86_REG_ZMM5, "zmm5" },
        { X86_REG_ZMM6, "zmm6" },
        { X86_REG_ZMM7, "zmm7" },
        { X86_REG_ZMM8, "zmm8" },
        { X86_REG_ZMM9, "zmm9" },
        { X86_REG_ZMM10, "zmm10" },
        { X86_REG_ZMM11, "zmm11" },
        { X86_REG_ZMM12, "zmm12" },
        { X86_REG_ZMM13, "zmm13" },
        { X86_REG_ZMM14, "zmm14" },
        { X86_REG_ZMM15, "zmm15" },
        { X86_REG_ZMM16, "zmm16" },
        { X86_REG_ZMM17, "zmm17" },
        { X86_REG_ZMM18, "zmm18" },
        { X86_REG_ZMM19, "zmm19" },
        { X86_REG_ZMM20, "zmm20" },
        { X86_REG_ZMM21, "zmm21" },
        { X86_REG_ZMM22, "zmm22" },
        { X86_REG_ZMM23, "zmm23" },
        { X86_REG_ZMM24, "zmm24" },
        { X86_REG_ZMM25, "zmm25" },
        { X86_REG_ZMM26, "zmm26" },
        { X86_REG_ZMM27, "zmm27" },
        { X86_REG_ZMM28, "zmm28" },
        { X86_REG_ZMM29, "zmm29" },
        { X86_REG_ZMM30, "zmm30" },
        { X86_REG_ZMM31, "zmm31" },
        { X86_REG_R8B, "r8b" },
        { X86_REG_R9B, "r9b" },
        { X86_REG_R10B, "r10b" },
        { X86_REG_R11B, "r11b" },
        { X86_REG_R12B, "r12b" },
        { X86_REG_R13B, "r13b" },
        { X86_REG_R14B, "r14b" },
        { X86_REG_R15B, "r15b" },
        { X86_REG_R8D, "r8d" },
        { X86_REG_R9D, "r9d" },
        { X86_REG_R10D, "r10d" },
        { X86_REG_R11D, "r11d" },
        { X86_REG_R12D, "r12d" },
        { X86_REG_R13D, "r13d" },
        { X86_REG_R14D, "r14d" },
        { X86_REG_R15D, "r15d" },
        { X86_REG_R8W, "r8w" },
        { X86_REG_R9W, "r9w" },
        { X86_REG_R10W, "r10w" },
        { X86_REG_R11W, "r11w" },
        { X86_REG_R12W, "r12w" },
        { X86_REG_R13W, "r13w" },
        { X86_REG_R14W, "r14w" },
        { X86_REG_R15W, "r15w" },
};

// register size in 64bit mode
const uint8_t regsize_map_64 [] = {
        0,	// 	{ X86_REG_INVALID, NULL },
        1,	// { X86_REG_AH, "ah" },
        1,	// { X86_REG_AL, "al" },
        2,	// { X86_REG_AX, "ax" },
        1,	// { X86_REG_BH, "bh" },
        1,	// { X86_REG_BL, "bl" },
        2,	// { X86_REG_BP, "bp" },
        1,	// { X86_REG_BPL, "bpl" },
        2,	// { X86_REG_BX, "bx" },
        1,	// { X86_REG_CH, "ch" },
        1,	// { X86_REG_CL, "cl" },
        2,	// { X86_REG_CS, "cs" },
        2,	// { X86_REG_CX, "cx" },
        1,	// { X86_REG_DH, "dh" },
        2,	// { X86_REG_DI, "di" },
        1,	// { X86_REG_DIL, "dil" },
        1,	// { X86_REG_DL, "dl" },
        2,	// { X86_REG_DS, "ds" },
        2,	// { X86_REG_DX, "dx" },
        4,	// { X86_REG_EAX, "eax" },
        4,	// { X86_REG_EBP, "ebp" },
        4,	// { X86_REG_EBX, "ebx" },
        4,	// { X86_REG_ECX, "ecx" },
        4,	// { X86_REG_EDI, "edi" },
        4,	// { X86_REG_EDX, "edx" },
        8,	// { X86_REG_EFLAGS, "flags" },
        4,	// { X86_REG_EIP, "eip" },
        4,	// { X86_REG_EIZ, "eiz" },
        2,	// { X86_REG_ES, "es" },
        4,	// { X86_REG_ESI, "esi" },
        4,	// { X86_REG_ESP, "esp" },
        10,	// { X86_REG_FPSW, "fpsw" },
        2,	// { X86_REG_FS, "fs" },
        2,	// { X86_REG_GS, "gs" },
        2,	// { X86_REG_IP, "ip" },
        8,	// { X86_REG_RAX, "rax" },
        8,	// { X86_REG_RBP, "rbp" },
        8,	// { X86_REG_RBX, "rbx" },
        8,	// { X86_REG_RCX, "rcx" },
        8,	// { X86_REG_RDI, "rdi" },
        8,	// { X86_REG_RDX, "rdx" },
        8,	// { X86_REG_RIP, "rip" },
        8,	// { X86_REG_RIZ, "riz" },
        8,	// { X86_REG_RSI, "rsi" },
        8,	// { X86_REG_RSP, "rsp" },
        2,	// { X86_REG_SI, "si" },
        1,	// { X86_REG_SIL, "sil" },
        2,	// { X86_REG_SP, "sp" },
        1,	// { X86_REG_SPL, "spl" },
        2,	// { X86_REG_SS, "ss" },
        8,	// { X86_REG_CR0, "cr0" },
        8,	// { X86_REG_CR1, "cr1" },
        8,	// { X86_REG_CR2, "cr2" },
        8,	// { X86_REG_CR3, "cr3" },
        8,	// { X86_REG_CR4, "cr4" },
        8,	// { X86_REG_CR5, "cr5" },
        8,	// { X86_REG_CR6, "cr6" },
        8,	// { X86_REG_CR7, "cr7" },
        8,	// { X86_REG_CR8, "cr8" },
        8,	// { X86_REG_CR9, "cr9" },
        8,	// { X86_REG_CR10, "cr10" },
        8,	// { X86_REG_CR11, "cr11" },
        8,	// { X86_REG_CR12, "cr12" },
        8,	// { X86_REG_CR13, "cr13" },
        8,	// { X86_REG_CR14, "cr14" },
        8,	// { X86_REG_CR15, "cr15" },
        8,	// { X86_REG_DR0, "dr0" },
        8,	// { X86_REG_DR1, "dr1" },
        8,	// { X86_REG_DR2, "dr2" },
        8,	// { X86_REG_DR3, "dr3" },
        8,	// { X86_REG_DR4, "dr4" },
        8,	// { X86_REG_DR5, "dr5" },
        8,	// { X86_REG_DR6, "dr6" },
        8,	// { X86_REG_DR7, "dr7" },
        10,	// { X86_REG_FP0, "fp0" },
        10,	// { X86_REG_FP1, "fp1" },
        10,	// { X86_REG_FP2, "fp2" },
        10,	// { X86_REG_FP3, "fp3" },
        10,	// { X86_REG_FP4, "fp4" },
        10,	// { X86_REG_FP5, "fp5" },
        10,	// { X86_REG_FP6, "fp6" },
        10,	// { X86_REG_FP7, "fp7" },
        2,	// { X86_REG_K0, "k0" },
        2,	// { X86_REG_K1, "k1" },
        2,	// { X86_REG_K2, "k2" },
        2,	// { X86_REG_K3, "k3" },
        2,	// { X86_REG_K4, "k4" },
        2,	// { X86_REG_K5, "k5" },
        2,	// { X86_REG_K6, "k6" },
        2,	// { X86_REG_K7, "k7" },
        8,	// { X86_REG_MM0, "mm0" },
        8,	// { X86_REG_MM1, "mm1" },
        8,	// { X86_REG_MM2, "mm2" },
        8,	// { X86_REG_MM3, "mm3" },
        8,	// { X86_REG_MM4, "mm4" },
        8,	// { X86_REG_MM5, "mm5" },
        8,	// { X86_REG_MM6, "mm6" },
        8,	// { X86_REG_MM7, "mm7" },
        8,	// { X86_REG_R8, "r8" },
        8,	// { X86_REG_R9, "r9" },
        8,	// { X86_REG_R10, "r10" },
        8,	// { X86_REG_R11, "r11" },
        8,	// { X86_REG_R12, "r12" },
        8,	// { X86_REG_R13, "r13" },
        8,	// { X86_REG_R14, "r14" },
        8,	// { X86_REG_R15, "r15" },
        10,	// { X86_REG_ST0, "st0" },
        10,	// { X86_REG_ST1, "st1" },
        10,	// { X86_REG_ST2, "st2" },
        10,	// { X86_REG_ST3, "st3" },
        10,	// { X86_REG_ST4, "st4" },
        10,	// { X86_REG_ST5, "st5" },
        10,	// { X86_REG_ST6, "st6" },
        10,	// { X86_REG_ST7, "st7" },
        16,	// { X86_REG_XMM0, "xmm0" },
        16,	// { X86_REG_XMM1, "xmm1" },
        16,	// { X86_REG_XMM2, "xmm2" },
        16,	// { X86_REG_XMM3, "xmm3" },
        16,	// { X86_REG_XMM4, "xmm4" },
        16,	// { X86_REG_XMM5, "xmm5" },
        16,	// { X86_REG_XMM6, "xmm6" },
        16,	// { X86_REG_XMM7, "xmm7" },
        16,	// { X86_REG_XMM8, "xmm8" },
        16,	// { X86_REG_XMM9, "xmm9" },
        16,	// { X86_REG_XMM10, "xmm10" },
        16,	// { X86_REG_XMM11, "xmm11" },
        16,	// { X86_REG_XMM12, "xmm12" },
        16,	// { X86_REG_XMM13, "xmm13" },
        16,	// { X86_REG_XMM14, "xmm14" },
        16,	// { X86_REG_XMM15, "xmm15" },
        16,	// { X86_REG_XMM16, "xmm16" },
        16,	// { X86_REG_XMM17, "xmm17" },
        16,	// { X86_REG_XMM18, "xmm18" },
        16,	// { X86_REG_XMM19, "xmm19" },
        16,	// { X86_REG_XMM20, "xmm20" },
        16,	// { X86_REG_XMM21, "xmm21" },
        16,	// { X86_REG_XMM22, "xmm22" },
        16,	// { X86_REG_XMM23, "xmm23" },
        16,	// { X86_REG_XMM24, "xmm24" },
        16,	// { X86_REG_XMM25, "xmm25" },
        16,	// { X86_REG_XMM26, "xmm26" },
        16,	// { X86_REG_XMM27, "xmm27" },
        16,	// { X86_REG_XMM28, "xmm28" },
        16,	// { X86_REG_XMM29, "xmm29" },
        16,	// { X86_REG_XMM30, "xmm30" },
        16,	// { X86_REG_XMM31, "xmm31" },
        32,	// { X86_REG_YMM0, "ymm0" },
        32,	// { X86_REG_YMM1, "ymm1" },
        32,	// { X86_REG_YMM2, "ymm2" },
        32,	// { X86_REG_YMM3, "ymm3" },
        32,	// { X86_REG_YMM4, "ymm4" },
        32,	// { X86_REG_YMM5, "ymm5" },
        32,	// { X86_REG_YMM6, "ymm6" },
        32,	// { X86_REG_YMM7, "ymm7" },
        32,	// { X86_REG_YMM8, "ymm8" },
        32,	// { X86_REG_YMM9, "ymm9" },
        32,	// { X86_REG_YMM10, "ymm10" },
        32,	// { X86_REG_YMM11, "ymm11" },
        32,	// { X86_REG_YMM12, "ymm12" },
        32,	// { X86_REG_YMM13, "ymm13" },
        32,	// { X86_REG_YMM14, "ymm14" },
        32,	// { X86_REG_YMM15, "ymm15" },
        32,	// { X86_REG_YMM16, "ymm16" },
        32,	// { X86_REG_YMM17, "ymm17" },
        32,	// { X86_REG_YMM18, "ymm18" },
        32,	// { X86_REG_YMM19, "ymm19" },
        32,	// { X86_REG_YMM20, "ymm20" },
        32,	// { X86_REG_YMM21, "ymm21" },
        32,	// { X86_REG_YMM22, "ymm22" },
        32,	// { X86_REG_YMM23, "ymm23" },
        32,	// { X86_REG_YMM24, "ymm24" },
        32,	// { X86_REG_YMM25, "ymm25" },
        32,	// { X86_REG_YMM26, "ymm26" },
        32,	// { X86_REG_YMM27, "ymm27" },
        32,	// { X86_REG_YMM28, "ymm28" },
        32,	// { X86_REG_YMM29, "ymm29" },
        32,	// { X86_REG_YMM30, "ymm30" },
        32,	// { X86_REG_YMM31, "ymm31" },
        64,	// { X86_REG_ZMM0, "zmm0" },
        64,	// { X86_REG_ZMM1, "zmm1" },
        64,	// { X86_REG_ZMM2, "zmm2" },
        64,	// { X86_REG_ZMM3, "zmm3" },
        64,	// { X86_REG_ZMM4, "zmm4" },
        64,	// { X86_REG_ZMM5, "zmm5" },
        64,	// { X86_REG_ZMM6, "zmm6" },
        64,	// { X86_REG_ZMM7, "zmm7" },
        64,	// { X86_REG_ZMM8, "zmm8" },
        64,	// { X86_REG_ZMM9, "zmm9" },
        64,	// { X86_REG_ZMM10, "zmm10" },
        64,	// { X86_REG_ZMM11, "zmm11" },
        64,	// { X86_REG_ZMM12, "zmm12" },
        64,	// { X86_REG_ZMM13, "zmm13" },
        64,	// { X86_REG_ZMM14, "zmm14" },
        64,	// { X86_REG_ZMM15, "zmm15" },
        64,	// { X86_REG_ZMM16, "zmm16" },
        64,	// { X86_REG_ZMM17, "zmm17" },
        64,	// { X86_REG_ZMM18, "zmm18" },
        64,	// { X86_REG_ZMM19, "zmm19" },
        64,	// { X86_REG_ZMM20, "zmm20" },
        64,	// { X86_REG_ZMM21, "zmm21" },
        64,	// { X86_REG_ZMM22, "zmm22" },
        64,	// { X86_REG_ZMM23, "zmm23" },
        64,	// { X86_REG_ZMM24, "zmm24" },
        64,	// { X86_REG_ZMM25, "zmm25" },
        64,	// { X86_REG_ZMM26, "zmm26" },
        64,	// { X86_REG_ZMM27, "zmm27" },
        64,	// { X86_REG_ZMM28, "zmm28" },
        64,	// { X86_REG_ZMM29, "zmm29" },
        64,	// { X86_REG_ZMM30, "zmm30" },
        64,	// { X86_REG_ZMM31, "zmm31" },
        1,	// { X86_REG_R8B, "r8b" },
        1,	// { X86_REG_R9B, "r9b" },
        1,	// { X86_REG_R10B, "r10b" },
        1,	// { X86_REG_R11B, "r11b" },
        1,	// { X86_REG_R12B, "r12b" },
        1,	// { X86_REG_R13B, "r13b" },
        1,	// { X86_REG_R14B, "r14b" },
        1,	// { X86_REG_R15B, "r15b" },
        4,	// { X86_REG_R8D, "r8d" },
        4,	// { X86_REG_R9D, "r9d" },
        4,	// { X86_REG_R10D, "r10d" },
        4,	// { X86_REG_R11D, "r11d" },
        4,	// { X86_REG_R12D, "r12d" },
        4,	// { X86_REG_R13D, "r13d" },
        4,	// { X86_REG_R14D, "r14d" },
        4,	// { X86_REG_R15D, "r15d" },
        2,	// { X86_REG_R8W, "r8w" },
        2,	// { X86_REG_R9W, "r9w" },
        2,	// { X86_REG_R10W, "r10w" },
        2,	// { X86_REG_R11W, "r11w" },
        2,	// { X86_REG_R12W, "r12w" },
        2,	// { X86_REG_R13W, "r13w" },
        2,	// { X86_REG_R14W, "r14w" },
        2,	// { X86_REG_R15W, "r15w" },
};

static const char *get_reg_name(int id){
    for (int i=0;i<234;i++){
        if (reg_name_maps[i].id==id){
            return reg_name_maps[i].name;
        }
    }
    return NULL;
}

static inline void print_mem_op(x86_op_mem *mem_op, GString *out){
    g_string_append_printf(out,"***op mem***\t segment_reg: %" PRIu32" , base_reg: 0x%" PRIu32 ", index: %" PRIu32 ", disp: 0x%lx, scale: 0x%x \n",
            mem_op->segment, mem_op->base,mem_op->index,mem_op->disp,mem_op->scale);
}