//
// Created by sina on 4/27/20.
//
#include <stdint.h>
#define GLOBAL_POOL_SIZE X86_REG_ENDING + 20
#include "taint_propagation.h"
#include "lib/utility.c"
#ifndef TAINTING_H
#define TAINTING_H

typedef struct{
    uint64_t src_val;
    uint64_t dst_val;
    uint64_t src2_val;
} inst_callback_values;

typedef struct{
    shad_inq src;
    shad_inq dst;
    instruction_operation operation;
    shad_inq src2;
    shad_inq src3; //When effective address calculation is needed e.g. LEA
    inst_callback_values *vals;
} inst_callback_argument;

typedef struct{
    char *operand;
    uint64_t *addr;
    uint64_t ip;
    inst_callback_argument *args;
    qemu_plugin_vcpu_udata_cb_t callback;
} mem_callback_argument;

typedef enum {
    BEFORE,
    AFTER,
    INMEM
} CB_TYPE;

static void taint_cb_mov(unsigned int cpu_index, void *udata);
static void taint_cb_clear(unsigned int cpu_index, void *udata);
static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata);
static void taint_cb_CMP(unsigned int cpu_index, void *udata);
static void taint_cb_XOR(unsigned int cpu_index, void *udata);
static void taint_cb_SR(unsigned int cpu_index, void *udata); //shift/rotate operations
static void taint_cb_EXTENDL(unsigned int cpu_index, void *udata);
static void taint_cb_XCHG(unsigned int cpu_index, void *udata);
static void taint_cb_AND_OR(unsigned int cpu_index, void *udata);
static void taint_cb_TEST(unsigned int cpu_index, void *udata);
static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata);
static void taint_cb_RET(unsigned int cpu_index, void *udata);
static void taint_cb_CALL(unsigned int cpu_index, void *udata);
static void taint_cb_JUMP(unsigned int cpu_index, void *udata);
static void taint_cb_CPUID(unsigned int cpu_index, void *udata);
static void taint_cb_RDTSC(unsigned int cpu_index, void *udata);
static void taint_cb_LEAVE(unsigned int cpu_index, void *udata);
static void taint_cb_movwf(unsigned int cpu_index, void *udata);
static void taint_cb_SETF(unsigned int cpu_index, void *udata);
static void taint_list_all(void);
GString *report;
#endif //QEMU_TAINTING_H
